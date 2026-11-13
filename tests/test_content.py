from pathlib import Path
import io
import tempfile
import unittest
import zipfile
from ingestion.content import Content
from ingestion.scanners import Blocked


class ContentTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def file(self,name,data):
        path=self.root/name;path.write_bytes(data);return path
    def archive(self,entries):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,raw in entries:archive.writestr(name,raw)
        return data.getvalue()
    def test_valid_text_image_and_pdf(self):
        from PIL import Image
        import pikepdf
        Content(self.root).inspect(self.file('good.txt',b'ordinary text'),'good.txt')
        image=self.root/'good.png';Image.new('RGB',(3,3)).save(image)
        Content(self.root).inspect(image,'good.png')
        pdf=self.root/'good.pdf'
        with pikepdf.Pdf.new() as document:document.add_blank_page();document.save(pdf)
        Content(self.root).inspect(pdf,'good.pdf')
    def test_corruption_type_mismatch_and_active_pdf_rejected(self):
        import pikepdf
        for name,raw in [('bad.png',b'not a PNG'),('bad.pdf',b'%PDF-1.7 truncated'),('bad.txt',b'\xff\x00')]:
            with self.assertRaises(Blocked):Content(self.root).inspect(self.file(name,raw),name)
        path=self.root/'active.pdf'
        with pikepdf.Pdf.new() as document:
            document.add_blank_page();document.Root.OpenAction=pikepdf.Dictionary(S=pikepdf.Name('/JavaScript'),JS='app.alert(1)');document.save(path)
        with self.assertRaises(Blocked):Content(self.root).inspect(path,'active.pdf')
    def test_archives_are_expanded_to_generated_paths(self):
        path=self.file('good.zip',self.archive([('nested/good.txt',b'ordinary content')]))
        items=Content(self.root).inspect(path,'good.zip')
        self.assertEqual(len(items),2);self.assertTrue(items[1][0].name.startswith('entry-'))
        self.assertEqual(items[1][1],'good.txt')
    def test_archive_traversal_scripts_and_bombs_rejected(self):
        for entries in [[('../bad.txt',b'x')],[('bad.php',b'<?php ?>')],[('bomb.txt',b'A'*1000000)]]:
            path=self.file('bad.zip',self.archive(entries))
            with self.assertRaises(Blocked):Content(self.root).inspect(path,'bad.zip')
    def test_office_relationships_and_missing_structure_rejected(self):
        path=self.file('missing.docx',self.archive([('test.txt',b'test')]))
        with self.assertRaises(Blocked):Content(self.root).inspect(path,'missing.docx')
        path=self.file('external.docx',self.archive([
            ('[Content_Types].xml',b'<Types/>'),('word/document.xml',b'<document/>'),
            ('_rels/.rels',b'<Relationships><Relationship TargetMode="External" Target="https://evil.invalid"/></Relationships>')]))
        with self.assertRaises(Blocked):Content(self.root).inspect(path,'external.docx')


if __name__=='__main__':unittest.main()
