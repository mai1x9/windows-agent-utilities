import tarfile
import os
import requests

url= ["https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-001-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-002-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-003-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-004-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-005-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-006-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-007-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-008-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-009-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-010-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-011-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-012-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-013-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-014-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-015-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-016-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-017-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-018-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-019-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-020-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-021-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-022-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-023-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-024-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-025-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-026-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-027-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-028-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-029-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-030-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-031-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-032-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-033-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-034-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-035-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-036-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-037-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-038-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-039-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-040-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-041-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-042-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-043-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-044-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-045-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-046-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-047-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-048-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-049-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-050-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-051-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-052-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-053-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-054-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-055-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-056-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-057-v5.tar.xz",
      "https://a4lg.com/downloads/vxshare/downloads/2015-07-24/vxshare-hashes-058-v5.tar.xz"]

for i in url:
    r = requests.get(i, stream=True)
    if r.status_code == 200:
        with open(os.path.basename(i), 'wb') as file:
            for chunk in r.raw.stream(1024, decode_content=False):
                if chunk:
                    file.write(chunk)
        if os.path.basename(i).endswith(".xz"):
            tar = tarfile.open(os.path.basename(i),"r:xz")
            tar.extractall()
            tar.close() 
        elif os.path.basename(i).endswith("tar.gz"):
            tar = tarfile.open(os.path.basename(i),"r:gz")
            tar.extractall()
            tar.close()
        os.remove(os.path.basename(i))   

path = r"C:\pythonprograms\targeturls\virusshare\vxshare-hashes\archives"
data = []

for root, dirs, files in os.walk(path):   
    for file in files:
        filenames= os.path.join(root,file)
        data.append(filenames)
    with open(r"C:\pythonprograms\targeturls\virusshare\final_file.txt","w",encoding="utf8") as f:
        for d in data:
            print(d)
            with open(d,"r") as f1:
                line = f1.read()
                line = line.replace(" ",",")
                f.write(line) 











