from unittest import TestCase
import unittest.mock as mock

from esrally import config
from esrally.mechanic import supplier


class SupplierTests(TestCase):
    @mock.patch("esrally.mechanic.supplier.GitRepository.head_revision", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.pull", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.clone", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.is_cloned", autospec=True)
    @mock.patch("esrally.utils.process.run_subprocess")
    def test_intial_checkout_latest(self, mock_run_subprocess, mock_is_cloned, mock_clone, mock_pull, mock_head_revision):
        cfg = config.Config()
        cfg.add(config.Scope.application, "source", "local.src.dir", "/src")
        cfg.add(config.Scope.application, "source", "remote.repo.url", "some-github-url")
        cfg.add(config.Scope.application, "source", "revision", "latest")

        mock_is_cloned.return_value = False
        mock_head_revision.return_value = "HEAD"

        git = supplier.GitRepository(cfg)

        s = supplier.Supplier(cfg, git)
        s.fetch()

        mock_is_cloned.assert_called_with(git)
        mock_clone.assert_called_with(git)
        mock_pull.assert_called_with(git)
        mock_head_revision.assert_called_with(git)

    @mock.patch("esrally.mechanic.supplier.GitRepository.head_revision", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.pull")
    @mock.patch("esrally.mechanic.supplier.GitRepository.clone")
    @mock.patch("esrally.mechanic.supplier.GitRepository.is_cloned", autospec=True)
    @mock.patch("esrally.utils.process.run_subprocess")
    def test_checkout_current(self, mock_run_subprocess, mock_is_cloned, mock_clone, mock_pull, mock_head_revision):
        cfg = config.Config()
        cfg.add(config.Scope.application, "source", "local.src.dir", "/src")
        cfg.add(config.Scope.application, "source", "remote.repo.url", "some-github-url")
        cfg.add(config.Scope.application, "source", "revision", "current")

        mock_is_cloned.return_value = True
        mock_head_revision.return_value = "HEAD"

        git = supplier.GitRepository(cfg)

        s = supplier.Supplier(cfg, git)
        s.fetch()

        mock_is_cloned.assert_called_with(git)
        mock_clone.assert_not_called()
        mock_pull.assert_not_called()
        mock_head_revision.assert_called_with(git)

    @mock.patch("esrally.mechanic.supplier.GitRepository.head_revision", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.pull_ts", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.is_cloned", autospec=True)
    @mock.patch("esrally.utils.process.run_subprocess")
    def test_checkout_ts(self, mock_run_subprocess, mock_is_cloned, mock_pull_ts, mock_head_revision):
        cfg = config.Config()
        cfg.add(config.Scope.application, "source", "local.src.dir", "/src")
        cfg.add(config.Scope.application, "source", "remote.repo.url", "some-github-url")
        cfg.add(config.Scope.application, "source", "revision", "@2015-01-01-01:00:00")

        mock_is_cloned.return_value = True
        mock_head_revision.return_value = "HEAD"

        git = supplier.GitRepository(cfg)

        s = supplier.Supplier(cfg, git)
        s.fetch()

        mock_is_cloned.assert_called_with(git)
        mock_pull_ts.assert_called_with(git, "2015-01-01-01:00:00")
        mock_head_revision.assert_called_with(git)

    @mock.patch("esrally.mechanic.supplier.GitRepository.head_revision", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.pull_revision", autospec=True)
    @mock.patch("esrally.mechanic.supplier.GitRepository.is_cloned", autospec=True)
    @mock.patch("esrally.utils.process.run_subprocess")
    def test_checkout_revision(self, mock_run_subprocess, mock_is_cloned, mock_pull_revision, mock_head_revision):
        cfg = config.Config()
        cfg.add(config.Scope.application, "source", "local.src.dir", "/src")
        cfg.add(config.Scope.application, "source", "remote.repo.url", "some-github-url")
        cfg.add(config.Scope.application, "source", "revision", "67c2f42")

        mock_is_cloned.return_value = True
        mock_head_revision.return_value = "HEAD"

        git = supplier.GitRepository(cfg)

        s = supplier.Supplier(cfg, git)
        s.fetch()

        mock_is_cloned.assert_called_with(git)
        mock_pull_revision.assert_called_with(git, "67c2f42")
        mock_head_revision.assert_called_with(git)
