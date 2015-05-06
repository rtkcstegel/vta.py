import unittest
import json
from vta import vtapi

class TestVTA(unittest.TestCase):
  def setUp(self):
    pass

  def test_print_scan_results(self):
    """Smoke test"""
    with open('virus_total_short_sample.json') as response_file:
      response = json.load(response_file)

    vtapi().print_scan_results(response)

if __name__ == '__main__':
  unittest.main()

