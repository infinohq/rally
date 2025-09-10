# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import warnings
from collections.abc import Iterable, Mapping
from typing import Any, Optional
import logging

from elastic_transport import (
    ApiResponse,
    BinaryApiResponse,
    HeadApiResponse,
    ListApiResponse,
    ObjectApiResponse,
    TextApiResponse,
)
from elastic_transport.client_utils import DEFAULT
from elasticsearch import Elasticsearch
from elasticsearch.compat import warn_stacklevel
from elasticsearch.exceptions import (
    HTTP_EXCEPTIONS,
    ApiError,
    ElasticsearchWarning,
    UnsupportedProductError,
)

from esrally.client.common import _WARNING_RE, _mimetype_header_to_compat, _quote_query
from esrally.utils import versions


# This reproduces the product verification behavior of v7.14.0 of the client:
# https://github.com/elastic/elasticsearch-py/blob/v7.14.0/elasticsearch/transport.py#L606
#
# As of v8.0.0, the client determines whether the server is Elasticsearch by checking
# whether HTTP responses contain the `X-elastic-product` header. If they do not, it raises
# an `UnsupportedProductError`. This header was only introduced in Elasticsearch 7.14.0,
# however, so the client will consider any version of ES prior to 7.14.0 unsupported due to
# responses not including it.
#
# Because Rally needs to support versions of ES >= 6.8.0, we resurrect the previous
# logic for determining the authenticity of the server, which does not rely exclusively
# on this header.
class _ProductChecker:
    """Class which verifies we're connected to a supported product"""

    # States that can be returned from 'check_product'
    SUCCESS = True
    UNSUPPORTED_PRODUCT = 2
    UNSUPPORTED_DISTRIBUTION = 3

    @classmethod
    def raise_error(cls, state, meta, body):
        # These states mean the product_check() didn't fail so do nothing.
        if state in (None, True):
            return

        if state == cls.UNSUPPORTED_DISTRIBUTION:
            message = "The client noticed that the server is not a supported distribution of Elasticsearch"
        else:  # UNSUPPORTED_PRODUCT
            message = "The client noticed that the server is not Elasticsearch and we do not support this unknown product"
        raise UnsupportedProductError(message, meta=meta, body=body)

    @classmethod
    def check_product(cls, headers, response):
        # type: (dict[str, str], dict[str, str]) -> int
        """
        Verifies that the server we're talking to is Elasticsearch.
        Does this by checking HTTP headers and the deserialized
        response to the 'info' API. Returns one of the states above.
        """

        version = response.get("version", {})
        try:
            version_number = versions.Version.from_string(version.get("number", None))
        except TypeError:
            # No valid 'version.number' field, either Serverless Elasticsearch, or not Elasticsearch at all
            version_number = versions.Version.from_string("0.0.0")

        build_flavor = version.get("build_flavor", None)

        # Check all of the fields and headers for missing/valid values.
        try:
            bad_tagline = response.get("tagline", None) != "You Know, for Search"
            bad_build_flavor = build_flavor not in ("default", "serverless")
            bad_product_header = headers.get("x-elastic-product", None) != "Elasticsearch"
        except (AttributeError, TypeError):
            bad_tagline = True
            bad_build_flavor = True
            bad_product_header = True

        # 7.0-7.13 and there's a bad 'tagline' or unsupported 'build_flavor'
        if versions.Version.from_string("7.0.0") <= version_number < versions.Version.from_string("7.14.0"):
            if bad_tagline:
                return cls.UNSUPPORTED_PRODUCT
            elif bad_build_flavor:
                return cls.UNSUPPORTED_DISTRIBUTION

        elif (
            # No version or version less than 6.8.0, and we're not talking to a serverless elasticsearch
            (version_number < versions.Version.from_string("6.8.0") and not versions.is_serverless(build_flavor))
            # 6.8.0 and there's a bad 'tagline'
            or (versions.Version.from_string("6.8.0") <= version_number < versions.Version.from_string("7.0.0") and bad_tagline)
            # 7.14+ and there's a bad 'X-Elastic-Product' HTTP header
            or (versions.Version.from_string("7.14.0") <= version_number and bad_product_header)
        ):
            return cls.UNSUPPORTED_PRODUCT

        return True


class RallySyncElasticsearch(Elasticsearch):
    def __init__(self, *args, **kwargs):
        distribution_version = kwargs.pop("distribution_version", None)
        distribution_flavor = kwargs.pop("distribution_flavor", None)
        self.database_type = kwargs.pop("database_type", "elasticsearch")
        super().__init__(*args, **kwargs)
        self._verified_elasticsearch = None
        self.distribution_version = distribution_version
        self.distribution_flavor = distribution_flavor
        self.logger = logging.getLogger(__name__)

    @property
    def is_serverless(self):
        return versions.is_serverless(self.distribution_flavor)

    def options(self, *args, **kwargs):
        new_self = super().options(*args, **kwargs)
        new_self.distribution_version = self.distribution_version
        new_self.distribution_flavor = self.distribution_flavor
        new_self.database_type = self.database_type
        return new_self

    def perform_request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Any] = None,
    ) -> ApiResponse[Any]:
        # We need to ensure that we provide content-type and accept headers
        if body is not None:
            if headers is None:
                headers = {"content-type": "application/json", "accept": "application/json"}
            else:
                if headers.get("content-type") is None:
                    headers["content-type"] = "application/json"
                if headers.get("accept") is None:
                    headers["accept"] = "application/json"

        if headers:
            request_headers = self._headers.copy()
            request_headers.update(headers)
        else:
            request_headers = self._headers

        # Skip product verification for non-Elasticsearch databases
        if self._verified_elasticsearch is None:
            if self.database_type == "elasticsearch":
                info = self.transport.perform_request(method="GET", target="/", headers=request_headers)
                info_meta = info.meta
                info_body = info.body

                if not 200 <= info_meta.status < 299:
                    raise HTTP_EXCEPTIONS.get(info_meta.status, ApiError)(message=str(info_body), meta=info_meta, body=info_body)

                self._verified_elasticsearch = _ProductChecker.check_product(info_meta.headers, info_body)

                if self._verified_elasticsearch is not True:
                    _ProductChecker.raise_error(self._verified_elasticsearch, info_meta, info_body)
            else:
                # Skip verification for OpenSearch and Infino
                self.logger.debug(f"Skipping product verification for database type: {self.database_type}")
                self._verified_elasticsearch = True

        routed_path, routed_params, routed_headers, routed_body = self._route_request(
            method, path, params, request_headers, body
        )

        # Converts all parts of a Accept/Content-Type headers
        # from application/X -> application/vnd.elasticsearch+X
        # see https://github.com/elastic/elasticsearch/issues/51816
        # Only apply Elasticsearch 8.x headers for actual Elasticsearch, not OpenSearch/Infino
        if not self.is_serverless and self.database_type == "elasticsearch":
            if versions.is_version_identifier(self.distribution_version) and (
                versions.Version.from_string(self.distribution_version) >= versions.Version.from_string("8.0.0")
            ):
                _mimetype_header_to_compat("Accept", routed_headers)
                _mimetype_header_to_compat("Content-Type", routed_headers)
        elif self.database_type == "opensearch":
            # OpenSearch needs both Accept and Content-Type headers but not the Elasticsearch 8.x format
            _mimetype_header_to_compat("Accept", routed_headers)
            _mimetype_header_to_compat("Content-Type", routed_headers)
        elif self.database_type == "infino":
            # Infino needs Content-Type but not Accept headers, and not the Elasticsearch 8.x format
            _mimetype_header_to_compat("Content-Type", routed_headers)

        # Handle params compatibility - newer elasticsearch-py doesn't accept params as kwarg
        if routed_params:
            # Merge params into the target URL
            from urllib.parse import urlencode
            param_string = urlencode(routed_params)
            if '?' in routed_path:
                routed_path = f"{routed_path}&{param_string}"
            else:
                routed_path = f"{routed_path}?{param_string}"
        
        resp = self.transport.perform_request(
            method=method, target=routed_path, headers=routed_headers, body=routed_body
        )
        resp_body, meta = resp.body, resp.meta
        
        # Transform response for database-specific differences
        transformed_body = self._transform_response(method, path, resp_body)

        # since this is used as an 'exists' functionality.
        if not (method == "HEAD" and meta.status == 404) and (
            not 200 <= meta.status < 299
            and (self._ignore_status is DEFAULT or self._ignore_status is None or meta.status not in self._ignore_status)
        ):
            message = str(resp_body)

            # If the response is an error response try parsing
            # the raw Elasticsearch error before raising.
            if isinstance(resp_body, dict):
                try:
                    error = resp_body.get("error", message)
                    if isinstance(error, dict) and "type" in error:
                        error = error["type"]
                    message = error
                except (ValueError, KeyError, TypeError):
                    pass

            raise HTTP_EXCEPTIONS.get(meta.status, ApiError)(message=message, meta=meta, body=resp_body)

        # 'Warning' headers should be reraised as 'ElasticsearchWarning'
        if "warning" in meta.headers:
            warning_header = (meta.headers.get("warning") or "").strip()
            warning_messages: Iterable[str] = _WARNING_RE.findall(warning_header) or (warning_header,)
            stacklevel = warn_stacklevel()
            for warning_message in warning_messages:
                warnings.warn(
                    warning_message,
                    category=ElasticsearchWarning,
                    stacklevel=stacklevel,
                )

        if isinstance(transformed_body, str):
            response = TextApiResponse(  # type: ignore[assignment]
                body=transformed_body,
                meta=meta,
            )
        elif isinstance(transformed_body, bytes):
            response = BinaryApiResponse(body=transformed_body, meta=meta)  # type: ignore[assignment]
        else:
            response = ApiResponse(body=transformed_body, meta=meta)  # type: ignore[assignment]

        return response

    def _route_request(self, method, path, params, headers, body):
        """Route requests based on database type and path"""
        
        if self.database_type == "elasticsearch":
            return path, params, headers, body
            
        elif self.database_type == "opensearch":
            return self._route_opensearch_request(method, path, params, headers, body)
            
        elif self.database_type == "infino":
            return self._route_infino_request(method, path, params, headers, body)
            
        else:
            self.logger.warning(f"Unknown database type: {self.database_type}, using default routing")
            return path, params, headers, body

    def _route_opensearch_request(self, method, path, params, headers, body):
        """Handle OpenSearch-specific request routing"""
        # OpenSearch is mostly Elasticsearch-compatible
        # Add any OpenSearch-specific routing here
        return path, params, headers, body

    def _route_infino_request(self, method, path, params, headers, body):
        """Handle Infino-specific request routing"""
        self.logger.debug(f"Routing Infino request: {method} {path}")
        
        # Add Infino authentication headers
        infino_headers = headers.copy() if headers else {}
        infino_headers.update({
            "Authorization": "Basic YWRtaW46RWVueS1tZWVueS1teW5pLW0w",
            "x-infino-client-cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM0akNDQWNxZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFpTVNBd0hnWURWUVFEREJkVFpXeG0KTFZOcFoyNWxaQ0JEWlhKMGFXWnBZMkYwWlRBZUZ3MHlOVEF6TVRBd016UTBNREphRncweU5qQXpNVEF3TXpRMApNREphTUNJeElEQWVCZ05WQkFNTUYxTmxiR1l0VTJsbmJtVmtJRU5sY25ScFptbGpZWFJsTUlJQklqQU5CZ2txCmhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBazd5M1FUNVIzQVRQNGx2elNzOXJJVGdOK2lGOTVFN3cKQ014QTlFcVc2bnRWRldBeEhzcCtqSDBEdUljS1pqeWNpQngrZnZIbmtqOTJsL21ZUjBIdGhVOUJKcElITFdUYQpJR2Q4YkZSTVdSOUF3RU1BNWluTVJQNVRZQS9xOE11YVc1Mmttb3M1MjAwTnVNMjVhaG9ueVBwb0ZKTnRZYmRhClhJeTZjd1kyMlVvSjBDa0R3cDR3U3hPMnprWFcwVlRrbkdLVXkyUXp6cWMzTTQxTzF2VDBXalp2UTlscmYzbEMKTFVISlNLL2luQlBIdG1IR1c0TndmTVg4U3UxSGpucFUyd0ZHSmk3TTUrNk5XMnBQZkd2Z1F2OHEvOG5qRUFrTgptUk9QWE5XYkNzTUllamF1WmxsbmxId3k4N1crNTJQTVRQWFhjdWlYS3l6WXVXMm9VZTJGZ1FJREFRQUJveU13CklUQWZCZ05WSFJFRUdEQVdnaFJoWTJOdmRXNTBPakF3TURBd01EQXdNREF3TURBTkJna3Foa2lHOXcwQkFRc0YKQUFPQ0FRRUFpaWJ2cjF5UVpVMmttRFBUbStZRkRlZ1VVaXZFckNYTkhhM3ZKWkhvU2N4WlZ5WWpwNzA5ZC96LwpNL3dubWFIRXU4RmVibTd0b1VVdERuN3R3MjBkRXZvTi9jV1RGQVhMYndJdXQxQmh0L0p1TGJrcUhUWVBCa3IvCjg0eHlzaWRVWVlCMC95eVVCaWRGTlVCbmc2R1RSYWMrV0dSVWtveGx6Ymw5WWpiOXF3QzNtSDNxb245azVZb2sKL2xqS29nZVpPTiswdUdIZExZM3FLVXN5QmE0UGpDK3dJWGY4Y1B2eHZlS1picUFZM002RFMzWUp6WWEyN05QVQozNFdEUCs2cSsraUJCRVFVbHZtTGovWmtZM1JSRlJpVXU2cFlPYlgvWjVFNzExMWFwQ0xiSnRYaVlWU3l4bzBKCnlVcUprdHBoTzZHTjAvNEJ1UmN4cnh5RkN1L0JWUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
            "x-infino-client-id": "rally-client",
            "x-infino-account-id": "000000000000",
            "x-infino-thread-id": "rally-thread",
            "x-infino-username": "admin",
        })
        
        # All operations work similarly to Elasticsearch
        return path, params, infino_headers, body
    
    def _transform_response(self, method, path, response_body):
        """Transform response based on database type to handle format differences"""
        
        if self.database_type == "elasticsearch":
            return response_body
            
        elif self.database_type == "opensearch":
            # OpenSearch responses are mostly Elasticsearch-compatible
            return response_body
            
        elif self.database_type == "infino":
            # Handle Infino-specific response format differences
            return self._transform_infino_response(method, path, response_body)
            
        return response_body
    
    def _transform_infino_response(self, method, path, response_body):
        """Transform Infino responses to be Rally-compatible"""
        
        if not isinstance(response_body, dict):
            return response_body
            
        # Handle cluster health responses
        if path == "/_cluster/health":
            # Ensure required fields exist for Rally
            if "status" not in response_body:
                response_body["status"] = "green"
            if "cluster_name" not in response_body:
                response_body["cluster_name"] = "infino-cluster"
                
        # Handle cluster stats responses  
        elif path == "/_cluster/stats":
            # Add missing fields that Rally expects
            if "cluster_name" not in response_body:
                response_body["cluster_name"] = "infino-cluster"
                
        # Handle node info responses
        elif "/_nodes" in path:
            # Ensure nodes response has expected structure
            if "nodes" not in response_body:
                response_body["nodes"] = {}
                
        # Handle search responses
        elif path.endswith("/_search") or "/_search" in path:
            # Ensure search response has expected structure
            if "hits" not in response_body:
                response_body["hits"] = {"total": {"value": 0}, "hits": []}
            elif isinstance(response_body.get("hits", {}).get("total"), int):
                # Convert old format total to new format
                total_value = response_body["hits"]["total"]
                response_body["hits"]["total"] = {"value": total_value, "relation": "eq"}
                
        # Handle bulk responses
        elif path.endswith("/_bulk") or "/_bulk" in path:
            # Ensure bulk response has expected structure
            if "items" not in response_body:
                response_body["items"] = []
                
        # Add debug logging for unexpected response formats
        self.logger.debug(f"Infino response for {method} {path}: {response_body}")
        
        return response_body
    

