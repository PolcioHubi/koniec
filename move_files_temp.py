import os
import shutil

source_dir = "C:/Users/kubio/Desktop/tstewinai6/mobywatelcreator/mobywatelcreator/mobywatelcreator/brakujeci pliki"
destination_dir = "C:/Users/kubio/Desktop/tstewinai6/mobywatelcreator/mobywatelcreator/mobywatelcreator/static"

files_to_move = [
    "arrow1.svg", "card.png", "checkbo.png", "checkmark.svg", "dowodnowy.css",
    "dowodnowybg.svg", "favicon.ico", "flaga.gif", "godlo.gif",
    "inter-cyrillic-400-normal.woff2", "inter-cyrillic-ext-400-normal.woff2",
    "inter-greek-400-normal.woff2", "inter-greek-ext-400-normal.woff2",
    "inter-latin-400-italic.woff2", "inter-latin-400-normal.woff2",
    "inter-latin-ext-400-normal.woff2", "jquery-3.6.0.min.js",
    "madziamojakotka123.svg", "magicznyjasieksigma.png", "main.css",
    "normal_u391.svg", "normal_u393.svg", "normal_u394.svg", "normal_u408.svg",
    "pesel.png", "pozdro.svg", "rozwijka.js", "scale.js", "sw.js",
    "timenew.js", "warstwa_1.png", "warstwa_2.png", "wybor.js"
]

for filename in files_to_move:
    source_path = os.path.join(source_dir, filename)
    destination_path = os.path.join(destination_dir, filename)
    try:
        if os.path.exists(source_path):
            shutil.move(source_path, destination_path)
            print(f"Przeniesiono: {filename}")
        else:
            print(f"Plik nie istnieje w źródle, pomijam: {filename}")
    except Exception as e:
        print(f"Błąd podczas przenoszenia {filename}: {e}")
