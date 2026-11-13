"""Conservative format validation and bounded ZIP/OOXML expansion.

Must run in the disposable resource-limited job process, never the web process.
"""
import codecs
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import posixpath
from urllib.parse import urlsplit,unquote
import uuid
import warnings
import zipfile

from ingestion.scanners import Blocked


def safe_name(name):
    if (not isinstance(name,str) or not name or len(name.encode())>240 or name.startswith('.')
        or re.search(r'[\x00-\x1f\x7f/\\:]',name) or name.endswith(('.', ' '))
        or re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)',name,re.I)):
        raise Blocked('unsafe_filename')
    return name


@dataclass
class Budget:
    entries:int=0
    expanded:int=0


class Content:
    TYPES=frozenset({'txt','png','jpg','jpeg','pdf','docx','xlsx','pptx','zip'})
    def __init__(self,work):self.work=Path(work);self.budget=Budget()

    @staticmethod
    def text(path):
        decoder=codecs.getincrementaldecoder('utf-8')('strict')
        try:
            with open(path,'rb') as source:
                while chunk:=source.read(65536):
                    if any(ord(c)<32 and c not in '\t\r\n' for c in decoder.decode(chunk)):
                        raise Blocked('invalid_text')
                decoder.decode(b'',final=True)
        except UnicodeError:raise Blocked('invalid_text')

    @staticmethod
    def image(path,extension):
        from PIL import Image,UnidentifiedImageError
        Image.MAX_IMAGE_PIXELS=25_000_000
        expected='PNG' if extension=='png' else 'JPEG'
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error',Image.DecompressionBombWarning)
                with Image.open(path,formats=[expected]) as image:
                    if getattr(image,'n_frames',1)!=1:raise Blocked('animated_image_not_allowed')
                    image.verify()
                with Image.open(path,formats=[expected]) as image:image.load()
        except (UnidentifiedImageError,OSError,ValueError,Image.DecompressionBombError,Image.DecompressionBombWarning):
            raise Blocked('invalid_image')

    @staticmethod
    def pdf(path):
        import pikepdf
        forbidden={'/JS','/JavaScript','/AA','/OpenAction','/Launch','/EmbeddedFiles','/EmbeddedFile',
            '/RichMedia','/XFA','/AcroForm','/SubmitForm','/ImportData','/URI','/GoToR','/GoToE','/Rendition','/Movie','/Sound','/3D','/AF','/EF'}
        try:
            with pikepdf.Pdf.open(path,password='',attempt_recovery=False) as pdf:
                if pdf.is_encrypted or len(pdf.objects)>10000 or len(pdf.pages)>1000 or pdf.check_pdf_syntax():
                    raise Blocked('uninspectable_pdf')
                visited=set();count=0
                def walk(obj,depth=0):
                    nonlocal count
                    if depth>128:raise Blocked('pdf_object_limit')
                    if not isinstance(obj,(pikepdf.Dictionary,pikepdf.Stream,pikepdf.Array)):return
                    if obj.is_indirect:
                        if obj.objgen in visited:return
                        visited.add(obj.objgen)
                    count+=1
                    if count>100000:raise Blocked('pdf_object_limit')
                    if isinstance(obj,pikepdf.Array):
                        for value in obj:walk(value,depth+1)
                    else:
                        if forbidden.intersection(str(key) for key in obj.keys()) or str(obj.get('/S','')) in forbidden or str(obj.get('/Type','')) in ('/EmbeddedFile','/Filespec'):raise Blocked('active_pdf_content')
                        for key in obj.keys():walk(obj[key],depth+1)
                for obj in pdf.objects:walk(obj)
        except (pikepdf.PdfError,pikepdf.PasswordError,ValueError):raise Blocked('invalid_pdf')

    @staticmethod
    def xml(path,logical_name=None,package_names=None):
        from defusedxml.ElementTree import fromstring
        from defusedxml.common import DefusedXmlException
        from xml.etree.ElementTree import ParseError
        if path.stat().st_size>4*1024**2:raise Blocked('xml_limit')
        try:
            root=fromstring(path.read_bytes(),forbid_dtd=True,forbid_entities=True,forbid_external=True)
            if logical_name=='[Content_Types].xml' and root.tag!='{http://schemas.openxmlformats.org/package/2006/content-types}Types':raise Blocked('invalid_office_xml')
            if logical_name and logical_name.endswith('.rels') and root.tag!='{http://schemas.openxmlformats.org/package/2006/relationships}Relationships':raise Blocked('invalid_office_xml')
            required={'word/document.xml':('document','wordprocessingml'),'xl/workbook.xml':('workbook','spreadsheetml'),'ppt/presentation.xml':('presentation','presentationml')}
            if logical_name in required:
                tag,family=required[logical_name]
                if root.tag not in (f'{{http://schemas.openxmlformats.org/{family}/2006/main}}{tag}',f'{{http://purl.oclc.org/ooxml/{family}/main}}{tag}'):raise Blocked('invalid_office_xml')
            count=0
            for item in root.iter():
                count+=1
                if count>100000:raise Blocked('xml_limit')
                if item.tag.rsplit('}',1)[-1].lower() in ('script','oleobject','externallink','object'):
                    raise Blocked('active_office_content')
                if any(k.rsplit('}',1)[-1]=='TargetMode' and v.lower()=='external' for k,v in item.attrib.items()):
                    raise Blocked('external_office_relationship')
                if logical_name and logical_name.endswith('.rels') and 'Target' in item.attrib:
                    target=unquote(item.attrib['Target']);uri=urlsplit(target)
                    if uri.scheme or uri.netloc or '\\' in target or target.startswith('/'):raise Blocked('external_office_relationship')
                    base=posixpath.dirname(logical_name).removesuffix('_rels').rstrip('/')
                    resolved=posixpath.normpath(posixpath.join(base,uri.path))
                    if resolved=='..' or resolved.startswith('../') or (package_names is not None and resolved not in package_names):raise Blocked('invalid_office_relationship')
                if any('macroenabled' in v.lower() for v in item.attrib.values()):raise Blocked('active_office_content')
        except (DefusedXmlException,ParseError,UnicodeError):raise Blocked('invalid_office_xml')

    def inspect(self,path,name,depth=0):
        safe_name(name);extension=name.rsplit('.',1)[-1].lower()
        if extension not in self.TYPES:raise Blocked('content_policy')
        if extension=='txt':self.text(path)
        elif extension in ('png','jpg','jpeg'):self.image(path,extension)
        elif extension=='pdf':self.pdf(path)
        else:return [(Path(path),name)]+self.archive(path,extension,depth)
        return [(Path(path),name)]

    def archive(self,path,extension,depth):
        if depth>=3:raise Blocked('archive_depth')
        with open(path,'rb') as source:
            if source.read(4) not in (b'PK\x03\x04',b'PK\x05\x06'):raise Blocked('invalid_archive')
            source.seek(0,2);size=source.tell();tail_size=min(size,65557);source.seek(-tail_size,2);tail=source.read(tail_size)
            end=tail.rfind(b'PK\x05\x06')
            if end<0 or end+22>len(tail) or end+22+struct.unpack('<H',tail[end+20:end+22])[0]!=len(tail):raise Blocked('invalid_archive')
        result=[]
        try:
            with zipfile.ZipFile(path) as archive:
                members=archive.infolist();names=set()
                if len(members)>1000:raise Blocked('archive_entry_limit')
                if extension!='zip':
                    required={'docx':'word/document.xml','xlsx':'xl/workbook.xml','pptx':'ppt/presentation.xml'}[extension]
                    package_names={m.filename for m in members}
                    if not {'[Content_Types].xml','_rels/.rels',required}<=package_names:raise Blocked('invalid_office_package')
                for member in members:
                    self.budget.entries+=1
                    if self.budget.entries>1000:raise Blocked('archive_entry_limit')
                    name=member.filename
                    if (name.casefold() in names or member.orig_filename!=name or '\\' in name or ':' in name
                        or name.startswith('/') or any(p in ('','..','.') for p in name.rstrip('/').split('/'))):raise Blocked('unsafe_archive_path')
                    names.add(name.casefold())
                    for part in name.rstrip('/').split('/'):
                        if not (extension!='zip' and part=='.rels'):safe_name(part)
                    if extension!='zip' and any(part.lower() in ('embeddings','activex') for part in name.split('/')):raise Blocked('active_office_content')
                    mode=member.external_attr>>16
                    if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR)):raise Blocked('unsafe_archive_entry')
                    if member.is_dir():continue
                    if member.flag_bits&1:raise Blocked('encrypted_archive')
                    if member.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):raise Blocked('unsupported_archive_compression')
                    if member.file_size<1 or member.file_size>32*1024**2 or member.file_size>max(1,member.compress_size)*100:
                        raise Blocked('archive_expansion_limit')
                    extracted=self.work/('entry-'+uuid.uuid4().hex)
                    with archive.open(member) as source,extracted.open('xb') as out:
                        size=0
                        while chunk:=source.read(65536):
                            size+=len(chunk);self.budget.expanded+=len(chunk)
                            if size>member.file_size or self.budget.expanded>128*1024**2:raise Blocked('archive_expansion_limit')
                            out.write(chunk)
                    if size!=member.file_size:raise Blocked('invalid_archive')
                    extracted.chmod(0o400)
                    basename=PurePosixPath(name).name
                    if extension!='zip' and (basename.lower().endswith(('.xml','.rels')) or basename=='[Content_Types].xml'):
                        self.xml(extracted,name,package_names);result.append((extracted,basename))
                    else:result.extend(self.inspect(extracted,basename,depth+1))
        except (zipfile.BadZipFile,RuntimeError,NotImplementedError,OSError):raise Blocked('invalid_archive')
        return result
