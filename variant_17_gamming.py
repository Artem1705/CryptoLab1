"""
ЛАБОРАТОРНАЯ РАБОТА: ВАРИАНТ 17 - «ГАММИРОВАНИЕ»
Раздел 2.5.5 методических указаний:
«2.5.5. ГАММИРОВАНИЕ (ШИФРОВАНИЕ С ПОМОЩЬЮ ДАТЧИКА ПСЕВДОСЛУЧАЙНЫХ ЧИСЕЛ)»

В методичке рассмотрены:
1. Конгруэнтные генераторы ПСЧ (ЛКГ):
   T(i + 1) = (A * T(i) + C) mod M,
   где A, C - константы, T(0) - начальное значение (ключ/порождающее число).
2. Наложение гаммы через операцию «исключающее ИЛИ» (XOR, по модулю 2):
   C[i] = P[i] ^ G[i],  P[i] = C[i] ^ G[i].
3. Наложение гаммы по модулю мощности алфавита N (для символьных сообщений):
   C[i] = (P[i] + G[i]) mod N,  P[i] = (C[i] - G[i]) mod N.
4. Метод гаммирования с обратной связью (OFB/CFB).
"""

import sys
from typing import List, Tuple, Union

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


class LCG_Generator:
    """
    Линейный конгруэнтный генератор (ЛКГ) датчика псевдослучайных чисел.
    Формула: T(i + 1) = (A * T(i) + C) mod M
    """
    def __init__(self, seed: int, a: int = 1664525, c: int = 1013904223, m: int = 2**32):
        self.state = seed % m
        self.a = a
        self.c = c
        self.m = m

    def next_val(self) -> int:
        """Вычисляет очередное значение T(i+1)"""
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def next_byte(self) -> int:
        """Получение псевдослучайного байта гаммы [0..255]"""
        return (self.next_val() >> 16) & 0xFF

    def next_mod_n(self, n: int) -> int:
        """Получение значения гаммы в кольце вычетов по модулю n [0..n-1]"""
        return (self.next_val() >> 16) % n


# ==============================================================================
# 1. ДВОИЧНОЕ ГАММИРОВАНИЕ (XOR, ПО МОДУЛЮ 2)
# ==============================================================================

class BinaryGamming:
    """
    Потоковое двоичное гаммирование с наложением побитовой операции XOR.
    Поддерживает произвольные строки UTF-8 и бинарные файлы.
    """
    def __init__(self, key_t0: int):
        self.key_t0 = key_t0

    def encrypt(self, data: Union[str, bytes]) -> Tuple[bytes, List[int]]:
        data_bytes = data.encode('utf-8') if isinstance(data, str) else bytes(data)
        lcg = LCG_Generator(self.key_t0)
        gamma = []
        ciphertext = bytearray()

        for b in data_bytes:
            g = lcg.next_byte()
            gamma.append(g)
            ciphertext.append(b ^ g)

        return bytes(ciphertext), gamma

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Благодаря свойствам XOR (a ^ b ^ b = a), расшифрование выполняется повторным наложением гаммы
        lcg = LCG_Generator(self.key_t0)
        plaintext = bytearray()

        for c_byte in ciphertext:
            g = lcg.next_byte()
            plaintext.append(c_byte ^ g)

        return bytes(plaintext)


# ==============================================================================
# 2. ГАММИРОВАНИЕ ПО МОДУЛЮ МОЩНОСТИ АЛФАВИТА (N = 33)
# ==============================================================================

class ModuloGamming:
    """
    Гаммирование по модулю алфавита русского языка (N = 33):
      C_i = (P_i + G_i) mod 33
      P_i = (C_i - G_i) mod 33
    """
    ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

    def __init__(self, key_t0: int):
        self.key_t0 = key_t0
        self.n = len(self.ALPHABET)
        self.char_to_idx = {char: idx for idx, char in enumerate(self.ALPHABET)}

    def encrypt(self, text: str) -> Tuple[str, List[int], List[int], List[int]]:
        lcg = LCG_Generator(self.key_t0)
        cipher_chars = []
        plain_indices = []
        gamma_values = []
        cipher_indices = []

        for ch in text.upper():
            if ch in self.char_to_idx:
                p_idx = self.char_to_idx[ch]
                g_val = lcg.next_mod_n(self.n)
                c_idx = (p_idx + g_val) % self.n

                plain_indices.append(p_idx)
                gamma_values.append(g_val)
                cipher_indices.append(c_idx)
                cipher_chars.append(self.ALPHABET[c_idx])
            else:
                cipher_chars.append(ch)

        return "".join(cipher_chars), plain_indices, gamma_values, cipher_indices

    def decrypt(self, ciphertext: str) -> str:
        lcg = LCG_Generator(self.key_t0)
        plain_chars = []

        for ch in ciphertext.upper():
            if ch in self.char_to_idx:
                c_idx = self.char_to_idx[ch]
                g_val = lcg.next_mod_n(self.n)
                p_idx = (c_idx - g_val) % self.n
                plain_chars.append(self.ALPHABET[p_idx])
            else:
                plain_chars.append(ch)

        return "".join(plain_chars)


def run_variant_17():
    print("=" * 78)
    print("  ВАРИАНТ 17: «ГАММИРОВАНИЕ» (Раздел 2.5.5 методички)")
    print("=" * 78)

    # Демонстрация 1: Побайтовое гаммирование (XOR)
    print("\n--- 1. ДВОИЧНОЕ ГАММИРОВАНИЕ С НАЛОЖЕНИЕМ ЧЕРЕЗ XOR ---")
    key_t0 = 123456789
    plaintext_xor = "ПРИКАЗ"

    xor_cipher = BinaryGamming(key_t0)
    ciphertext_bytes, gamma_bytes = xor_cipher.encrypt(plaintext_xor)

    print(f"[+] Исходное сообщение:             '{plaintext_xor}'")
    print(f"[+] Начальный ключ датчика (T0):    {key_t0}")
    print(f"[+] Сгенерированная гамма (байты):  {gamma_bytes}")
    print(f"[+] Шифртекст (HEX):                {ciphertext_bytes.hex().upper()}")

    decrypted_bytes = xor_cipher.decrypt(ciphertext_bytes)
    decrypted_text = decrypted_bytes.decode('utf-8')
    print(f"[+] Расшифрованный текст:           '{decrypted_text}'")
    assert decrypted_text == plaintext_xor, "Ошибка в двоичном гаммировании!"
    print("[OK] Тест двоичного гаммирования (XOR) успешно пройден!\n")

    # Демонстрация 2: Модульное гаммирование (по алфавиту)
    print("--- 2. ГАММИРОВАНИЕ ПО МОДУЛЮ МОЩНОСТИ АЛФАВИТА (N = 33) ---")
    seed_alpha = 987654321
    plaintext_alpha = "ПРИКАЗ"

    mod_cipher = ModuloGamming(seed_alpha)
    cipher_res, p_idx, gamma_idx, c_idx = mod_cipher.encrypt(plaintext_alpha)

    print(f"[+] Исходный текст:                 '{plaintext_alpha}'")
    print(f"[+] Начальный ключ датчика (T0):    {seed_alpha}")
    print(f"[+] Коды символов открытого текста: {p_idx}")
    print(f"[+] Значения гаммы:                 {gamma_idx}")
    print(f"[+] Коды символов шифртекста:       {c_idx}")
    print(f"[+] Правило: C_i = (P_i + G_i) mod 33")
    print(f"[+] Итоговый зашифрованный текст:   '{cipher_res}'")

    decrypted_alpha = mod_cipher.decrypt(cipher_res)
    print(f"[+] Расшифрованный текст:           '{decrypted_alpha}'")
    assert decrypted_alpha == plaintext_alpha, "Ошибка в модульном гаммировании!"
    print("[OK] Тест модульного гаммирования успешно пройден!")
    print("=" * 78)


if __name__ == "__main__":
    run_variant_17()
