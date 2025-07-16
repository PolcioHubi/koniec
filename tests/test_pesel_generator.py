import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
from pesel_generator import generate_pesel, validate_pesel, extract_info_from_pesel

def test_generate_pesel_male():
    birth_date = "01.01.1990"
    gender = "Mężczyzna"
    pesel = generate_pesel(birth_date, gender)
    assert len(pesel) == 11
    assert validate_pesel(pesel) is True
    info = extract_info_from_pesel(pesel)
    assert info["gender"] == gender
    assert info["birth_date"] == birth_date
    assert info["year"] == 1990
    assert info["month"] == 1
    assert info["day"] == 1

def test_generate_pesel_female():
    birth_date = "01.01.1990"
    gender = "Kobieta"
    pesel = generate_pesel(birth_date, gender)
    assert len(pesel) == 11
    assert validate_pesel(pesel) is True
    info = extract_info_from_pesel(pesel)
    assert info["gender"] == gender
    assert info["birth_date"] == birth_date
    assert info["year"] == 1990
    assert info["month"] == 1
    assert info["day"] == 1

def test_generate_pesel_different_century():
    birth_date = "01.01.2000"
    gender = "Mężczyzna"
    pesel = generate_pesel(birth_date, gender)
    assert len(pesel) == 11
    assert validate_pesel(pesel) is True
    info = extract_info_from_pesel(pesel)
    assert info["birth_date"] == birth_date
    assert info["year"] == 2000
    assert info["month"] == 1
    assert info["day"] == 1

def test_validate_pesel_invalid_length():
    assert validate_pesel("123") is False

def test_validate_pesel_invalid_checksum():
    # A valid PESEL with one digit changed to make checksum invalid
    assert validate_pesel("90010112346") is False

def test_validate_pesel_dynamic_invalid_checksum():
    # Generate a valid PESEL
    valid_pesel = generate_pesel("01.01.1990", "Mężczyzna")
    # Change a non-checksum digit to make it invalid
    invalid_pesel = list(valid_pesel)
    invalid_pesel[0] = str((int(invalid_pesel[0]) + 1) % 10) # Change first digit
    invalid_pesel = "".join(invalid_pesel)
    assert validate_pesel(invalid_pesel) is False

def test_extract_info_from_pesel_invalid_pesel():
    assert extract_info_from_pesel("invalid") is None

def test_extract_info_from_pesel_male():
    pesel = generate_pesel("15.03.1985", "Mężczyzna")
    info = extract_info_from_pesel(pesel)
    assert info["birth_date"] == "15.03.1985"
    assert info["gender"] == "Mężczyzna"

def test_extract_info_from_pesel_female():
    pesel = generate_pesel("20.07.1995", "Kobieta")
    info = extract_info_from_pesel(pesel)
    assert info["birth_date"] == "20.07.1995"
    assert info["gender"] == "Kobieta"

def test_extract_info_from_pesel_21st_century():
    pesel = generate_pesel("10.11.2005", "Mężczyzna")
    info = extract_info_from_pesel(pesel)
    assert info["birth_date"] == "10.11.2005"

def test_generate_pesel_invalid_date():
    with pytest.raises(ValueError, match="Błąd w generowaniu PESEL"):
        generate_pesel("32.01.1990", "Mężczyzna")

def test_generate_pesel_unsupported_year():
    with pytest.raises(ValueError, match="Rok 1700 nie jest obsługiwany przez algorytm PESEL"):
        generate_pesel("01.01.1700", "Mężczyzna")
