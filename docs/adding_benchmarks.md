### Adding new benchmarks to Rally

#### Overview

Although it is possible to add new benchmarks to Rally, it is needed to [set up Rally in development mode first](developing.md). We will 
eventually [split benchmark specifications from Rally](https://github.com/elastic/rally/issues/26) but the API is currently not stable 
enough to support this reliably.

First of all we need to clarify what a benchmark is. Rally has a few assumptions built-in:

1. Rally sets up a fresh Elasticsearch cluster, i.e. the cluster is entirely under Rally's control.
2. The first step of the benchmark is to index all required documents via the 
[bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html). Rally will measure metrics like
indexing throughput in this phase.
3. An optional second step is to run one or more queries against the index. Rally will measure metrics like query latency in this phase.

A benchmark is called a "track" in Rally. The most important attributes of a track are:

* One index name with one type in it
* The queries to issue
* Source URL of the benchmark data
* A list of track setups

A "track setup" defines custom settings of the benchmark candidate (Elasticsearch) for this track, like how much heap memory to use, the
number of nodes to start and so on. Rally comes with a set of default track setups which you can use for your own benchmarks (but you don't
have to).

#### Example benchmark

Let's create an example benchmark step by step. First of all, we need some data. There are a lot of public data sets available which are
interesting for new benchmarks and we also have a [backlog of benchmarks to add](https://github.com/elastic/rally/issues?q=is%3Aissue+is%3Aopen+label%3A%3ABenchmark).

[Geonames](http://www.geonames.org/) provided geo data under a [creative commons license](http://creativecommons.org/licenses/by/3.0/). We
will download [allCountries.zip](http://download.geonames.org/export/dump/allCountries.zip) (around 300MB), extract it and inspect `allCountries.txt`.

You will note that the file is tab-delimited but we need JSON to bulk-index data with Elasticsearch. So we can use a small script to do the
conversion for us:

```
import json
import csv

cols = (('geonameid', 'int'),
       ('name', 'string'),
       ('asciiname', 'string'),
       ('alternatenames', 'string'),
       ('latitude', 'double'),
       ('longitude', 'double'),
       ('feature_class', 'string'),
       ('feature_code', 'string'),
       ('country_code', 'string'),
       ('cc2', 'string'),
       ('***REMOVED***1_code', 'string'),
       ('***REMOVED***2_code', 'string'),
       ('***REMOVED***3_code', 'string'),
       ('***REMOVED***4_code', 'string'),
       ('population', 'long'),
       ('elevation', 'int'),
       ('dem', 'string'),
       ('timezone', 'string'))
       
with open('allCountries.txt') as f:
 while True:
   line = f.readline()
   if line == '':
     break
   tup = line.strip().split('\t')
   d = {}
   for i in range(len(cols)):
     name, type = cols[i]
     if tup[i] != '':
       if type in ('int', 'long'):
         d[name] = int(tup[i])
       elif type == 'double':
         d[name] = float(tup[i])
       else:
         d[name] = tup[i]

   print(json.dumps(d))
```

We can invoke the script with `python3 toJSON.py > documents.json`. Next we need to compress the JSON file with `
bzip2 -9 -c documents.json > documents.json.bz2.

Next we need a mapping file for these documents. For details on how to write a mapping file, see 
[the Elasticsearch documentation on mappings](https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping.html) and look at the
 [example mapping file](http://benchmarks.elastic.co/corpora/geonames/mappings.json).

Now ensure to create a file called "README.txt" which can contain more information about a benchmark and must contain license information.

Now upload all three files to a place where it is publicly available. We choose `http://benchmarks.elastic.co/corpora/geonames` for this example.

Finally, add a new Python source file in Rally's project directory. By convention, the file should be called "$BENCHMARK_NAME_track.py", so
for our example the file is called "geonames_track.py". It is placed in "rally/track/".

```
from rally.track import track


class SampleQuery(track.Query):
    def __init__(self):
        track.Query.__init__(self, "sample")

    def run(self, es):
        return es.search(index=geonamesTrackSpec.index_name)

geonamesTrackSpec = track.Track(
    name="geonames",
    description="This test indexes 8.6M documents (POIs from Geonames, total 2.8 GB json) using 8 client threads and 5000 docs per bulk "
                "request against Elasticsearch",
    source_root_url="http://benchmarks.elastic.co/corpora/geonames",
    index_name="geonames",
    type_name="type",
    number_of_documents=8647880,
    compressed_size_in_bytes=197857614,
    uncompressed_size_in_bytes=2790927196,
    document_file_name="documents.json.bz2",
    mapping_file_name="mappings.json",
    estimated_benchmark_time_in_minutes=20,
    # Queries to use in the search benchmark
    queries=[SampleQuery()],
    track_setups=track.track_setups
```

A few things to note:

* You can either use the standard track setups provided with Rally or add your own. Note that Rally assumes that the track setup that should
 be run by default is called "defaults". It is possible to not use this name but it is more convenient for users.
* You can add as many searches as you want. We use the [official Python Elasticsearch client](http://elasticsearch-py.readthedocs.org/) to issue
  queries.
* `estimated_benchmark_time_in_minutes` is really just a ballpark estimate to give users a very rough idea how the long the benchmark will run.
* The numbers are needed to verify integrity and provide progress reports.

When you invoke `esrally list tracks`, the new track should now appear:

```
dm@io:~ $ esrally list tracks

    ____        ____
   / __ \____ _/ / /_  __
  / /_/ / __ `/ / / / / /
 / _, _/ /_/ / / / /_/ /
/_/ |_|\__,_/_/_/\__, /
                /____/
Available tracks:

* geonames: This test indexes 8.6M documents (POIs from Geonames, total 2.8 GB json) using 8 client threads and 5000 docs per bulk 
request against Elasticsearch
	Track setups for this track:
	* defaults
	* 4gheap
	* fastsettings
	* fastupdates
	* two_nodes_defaults
	* defaults_verbose_iw
```

Congratulations, you have created your first track! You can test it with `esrally --track=geonames` (or whatever the name of your track is).
 
If you want to share it with the community, please read on.

#### How to contribute a benchmark

First of all, please read the [contributors guide](https://github.com/elastic/rally/blob/master/CONTRIBUTING.md).

When you want to contribute your benchmark, follow these steps:

1. Create a track file as described above
2. Upload the associated data so they can be publicly downloaded via HTTP. The data have to include four files: the actual benchmark
 data (either as .bz2 (recommended) or as .zip), the mapping file, a license file called "LICENSE.txt" and a readme, called "README.txt". 
 Note that pull requests without a license cannot be accepted.
3. Create a pull request for the [Rally Github repo](https://github.com/elastic/rally).