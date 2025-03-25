import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime
from trivy_discovery import upload_sc_trivy_scan_results


class TestUploadScTrivyScanResults(unittest.TestCase):
  @patch('trivy_discovery.datetime')
  def test_successful_upload_with_environments(self, mock_datetime):
    mock_now = MagicMock()
    mock_now.isoformat.return_value = '2023-01-01T12:00:00'
    mock_datetime.now.return_value = mock_now

    # Mock ServiceCatalogue
    mock_sc = MagicMock()
    mock_sc.add.return_value = {'data': {'id': 123}}
    mock_sc.get_record_list.return_value = [{'id': 1}, {'id': 2}]
    mock_sc.update.return_value = True

    # Call the function
    upload_sc_trivy_scan_results('component1', 'v1.0', {'result': 'data'}, mock_sc)

    # Assertions
    mock_sc.add.assert_called_once_with(
      'trivy-scans?populate=*',
      {
        'name': 'component1',
        'trivy_scan_results': {'result': 'data'},
        'build_image_tag': 'v1.0',
        'trivy_scan_timestamp': '2023-01-01T12:00:00',
      },
    )
    mock_sc.get_record_list.assert_called_once_with(
      'environments?populate=component', 'component][name', 'component1'
    )
    mock_sc.update.assert_any_call('environments', 1, {'trivy_scan': 123})
    mock_sc.update.assert_any_call('environments', 2, {'trivy_scan': 123})

  @patch('trivy_discovery.datetime')
  def test_successful_upload_no_environments(self, mock_datetime):
    mock_now = MagicMock()
    mock_now.isoformat.return_value = '2023-01-01T12:00:00'
    mock_datetime.now.return_value = mock_now

    # Mock ServiceCatalogue
    mock_sc = MagicMock()
    mock_sc.add.return_value = {'data': {'id': 123}}
    mock_sc.get_record_list.return_value = []

    # Call the function
    upload_sc_trivy_scan_results('component1', 'v1.0', {'result': 'data'}, mock_sc)

    # Assertions
    mock_sc.add.assert_called_once_with(
      'trivy-scans?populate=*',
      {
        'name': 'component1',
        'trivy_scan_results': {'result': 'data'},
        'build_image_tag': 'v1.0',
        'trivy_scan_timestamp': '2023-01-01T12:00:00',
      },
    )
    mock_sc.get_record_list.assert_called_once_with(
      'environments?populate=component', 'component][name', 'component1'
    )
    mock_sc.update.assert_not_called()

  @patch('trivy_discovery.datetime')
  def test_upload_fails_no_trivy_scan_id(self, mock_datetime):
    mock_now = MagicMock()
    mock_now.isoformat.return_value = '2023-01-01T12:00:00'
    mock_datetime.now.return_value = mock_now

    # Mock ServiceCatalogue
    mock_sc = MagicMock()
    mock_sc.add.return_value = {'data': {}}

    # Call the function
    upload_sc_trivy_scan_results('component1', 'v1.0', {'result': 'data'}, mock_sc)

    # Assertions
    mock_sc.add.assert_called_once_with(
      'trivy-scans?populate=*',
      {
        'name': 'component1',
        'trivy_scan_results': {'result': 'data'},
        'build_image_tag': 'v1.0',
        'trivy_scan_timestamp': '2023-01-01T12:00:00',
      },
    )
    mock_sc.get_record_list.assert_not_called()
    mock_sc.update.assert_not_called()

  @patch('trivy_discovery.datetime')
  def test_upload_fails_add_returns_none(self, mock_datetime):
    mock_now = MagicMock()
    mock_now.isoformat.return_value = '2023-01-01T12:00:00'
    mock_datetime.now.return_value = mock_now

    # Mock ServiceCatalogue
    mock_sc = MagicMock()
    mock_sc.add.return_value = None

    # Call the function
    upload_sc_trivy_scan_results('component1', 'v1.0', {'result': 'data'}, mock_sc)

    # Assertions
    mock_sc.add.assert_called_once_with(
      'trivy-scans?populate=*',
      {
        'name': 'component1',
        'trivy_scan_results': {'result': 'data'},
        'build_image_tag': 'v1.0',
        'trivy_scan_timestamp': '2023-01-01T12:00:00',
      },
    )
    mock_sc.get_record_list.assert_not_called()
    mock_sc.update.assert_not_called()


if __name__ == '__main__':
  unittest.main()
