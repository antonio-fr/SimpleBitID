rd /S /Q build
rd /S /Q dist
c:\python27_32\python.exe setupINSTALL.py py2exe
c:\python27_32\python.exe setup.py py2exe
copy c:\Python27_32\Lib\msvcp90.dll dist
cd dist
"C:\Program Files\7-Zip\7z.exe" a -m0=LZMA2 SBID.7z *
cd ..
"C:\Program Files\7z SFX Builder\7z SFX Builder.exe" SFX_data.txt