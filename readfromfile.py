

import glob

# Pfad zum Verzeichnis, in dem die Dateien gesucht werden sollen
path = "data/patternspid/"
# Alle .txt-Dateien im Verzeichnis auflisten
txt_files = glob.glob(path + "*.txt")

if txt_files:
    # Erste gefundene .txt-Datei öffnen und lesen
    with open(txt_files[0], "r") as file:
        lines = file.readlines()

    for line in lines:
        print(line)
else:
    print("Keine .txt-Dateien gefunden.")