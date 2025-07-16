# Przykładowe dane testowe dla aplikacji Flask
# Wszystko z dużych liter oprócz danych dodatkowych

example_data = {
    # Dane osobowe - DUŻE LITERY
    'imie': 'PIOTR',
    'nazwisko': 'KOWALSKI',
    'obywatelstwo': 'POLSKIE',
    'data_urodzenia': '15.03.1985',
    'pesel': '85031512345',
    
    # Dane mDowodu - DUŻE LITERY
    'seria_numer_mdowod': 'TRF123456',
    'termin_waznosci_mdowod': '2030-03-15',
    'data_wydania_mdowod': '2020-03-15',
    'imie_ojca_mdowod': 'JANUSZ',
    'imie_matki_mdowod': 'ANNA',
    
    # Dane dowodu osobistego - DUŻE LITERY
    'seria_numer_dowod': 'ABC123456',
    'termin_waznosci_dowod': '2030-03-15',
    'data_wydania_dowod': '2020-03-15',
    
    # Dane dodatkowe - normalne litery (zgodnie z żądaniem)
    'nazwisko_rodowe': 'Kowalski',
    'plec': 'Mężczyzna',
    'nazwisko_rodowe_ojca': 'Kowalski',
    'nazwisko_rodowe_matki': 'Nowak',
    'miejsce_urodzenia': 'Warszawa',
    'adres_zameldowania': 'ul. Testowa 123\n00-001 Warszawa',
    'data_zameldowania': '2020-01-15',
}

# Funkcja do wypełnienia formularza przykładowymi danymi
def get_example_data():
    return example_data

# Funkcja do wyświetlenia przykładowych danych
def print_example_data():
    print("Przykładowe dane testowe:")
    print("=" * 50)
    for key, value in example_data.items():
        print(f"{key}: {value}")
    print("=" * 50)

if __name__ == "__main__":
    print_example_data()

