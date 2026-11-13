from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


class AppPackageTests(unittest.TestCase):
    def test_metadata_and_registered_entrypoints_are_present(self):
        root = Path(__file__).parents[1] / "nextcloud/nextshuttle"
        metadata = ET.parse(root / "appinfo/info.xml").getroot()
        self.assertEqual(metadata.findtext("id"), root.name)
        self.assertEqual(metadata.findtext("namespace"), "NextShuttle")
        for tag in ("background-jobs/job", "commands/command", "settings/admin"):
            for entry in metadata.findall(tag):
                self.assertTrue(entry.text.startswith("OCA\\NextShuttle\\"))
                path = root / "lib" / (entry.text.removeprefix("OCA\\NextShuttle\\").replace("\\", "/") + ".php")
                self.assertTrue(path.is_file(), str(path))
        self.assertTrue((root / "img/app.svg").is_file())


if __name__ == "__main__":
    unittest.main()
