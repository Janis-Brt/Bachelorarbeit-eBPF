

import glob

# Pfad zum Verzeichnis, in dem die Dateien gesucht werden sollen
path = "data/patternspid/"
path2 = "data/patternstgid"
# Alle .txt-Dateien im Verzeichnis auflisten
txt_files = glob.glob(path + "*.txt")

if txt_files:
    # Erste gefundene .txt-Datei öffnen und lesen
    with open(path, "r") as file:
        lines = file.readlines()
    with open(path2, "r") as file:
        lines2 = file.readlines()

    for line in lines:
        print(line)
    print("++++++++++++++++++++++++++++++++++++++++++++++")
    for line in lines2:
        print(line)
else:
    print("Keine .txt-Dateien gefunden.")