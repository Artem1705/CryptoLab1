"""
ЛАБОРАТОРНАЯ РАБОТА: ВАРИАНТ 16 - «ШИФРОВАНИЕ АЛГОРИТМОМ»

В методическом пособии в списке вариантов строка 5 / 11 / 16 обозначена как:
«Шифрование алгоритмом.»
В теоретической части этой строке соответствует Раздел 2.7 «Комбинированные методы»:
- Шифр Д. Френдберга (комбинация многоалфавитной подстановки и генератора ПСЧ / гаммы).
- Система ЛЮЦИФЕР (комбинация S-блоков подстановки и P-блоков перестановок).
Также в методичке подробно описан потоковый алгоритм WAKE (Раздел 2.6.3).

В данном модуле реализованы:
1. Основной: Комбинированный алгоритм шифрования Д. Френдберга (Раздел 2.7).
2. Потоковый алгоритм WAKE (Word Auto Key Encryption, Раздел 2.6.3).
"""

import sys
from typing import List, Tuple

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ==============================================================================
# ЧАСТЬ 1. КОМБИНИРОВАННЫЙ АЛГОРИТМ (ШИФР Д. ФРЕНДБЕРГА, РАЗДЕЛ 2.7)
# ==============================================================================

class FreindbergCipher:
    """
    Шифр Д. Френдберга (Раздел 2.7 методички).
    Комбинирует два криптографических преобразования:
      Шаг 1: Многоалфавитная подстановка (полиалфавитный шифр на основе ключа).
      Шаг 2: Наложение гаммы, выработанной датчиком ПСЧ (конгруэнтным генератором).
    Особенность: выравнивает частотные характеристики символов шифртекста,
    делая его невосприимчивым к частотному криптоанализу.
    """
    ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

    def __init__(self, key_word: str = "КЛЮЧ", prng_seed: int = 555777):
        """
        :param key_word: Ключ для этапа многоалфавитной подстановки.
        :param prng_seed: Начальное порождающее число (T0) для датчика ПСЧ.
        """
        self.key_word = key_word.upper()
        self.prng_seed = prng_seed
        self.n = len(self.ALPHABET)
        self.char_to_idx = {ch: idx for idx, ch in enumerate(self.ALPHABET)}

    def _generate_gamma(self, length: int) -> List[int]:
        """Линейный конгруэнтный датчик: T(i+1) = (A * T(i) + C) mod M"""
        state = self.prng_seed
        gamma = []
        for _ in range(length):
            state = (1664525 * state + 1013904223) % (2**32)
            # Приводим к диапазону мощности алфавита [0, N-1]
            gamma.append((state >> 16) % self.n)
        return gamma

    def encrypt(self, plaintext: str) -> Tuple[str, str, str, List[int]]:
        """
        Зашифрование:
        1. Подстановка: S[i] = (P[i] + K[i]) mod N
        2. Гаммирование: C[i] = (S[i] + G[i]) mod N
        """
        text_upper = plaintext.upper()
        letters = [ch for ch in text_upper if ch in self.char_to_idx]
        key_len = len(self.key_word)
        gamma = self._generate_gamma(len(letters))

        # Шаг 1: Подстановка
        step1_chars = []
        for i, ch in enumerate(letters):
            p_val = self.char_to_idx[ch]
            k_val = self.char_to_idx[self.key_word[i % key_len]]
            s_val = (p_val + k_val) % self.n
            step1_chars.append(self.ALPHABET[s_val])
        step1_text = "".join(step1_chars)

        # Шаг 2: Наложение гаммы
        step2_chars = []
        for i, ch in enumerate(step1_chars):
            s_val = self.char_to_idx[ch]
            g_val = gamma[i]
            c_val = (s_val + g_val) % self.n
            step2_chars.append(self.ALPHABET[c_val])
        step2_text = "".join(step2_chars)

        # Восстановление форматирования (пробелы, знаки препинания)
        final_chars = []
        c_i = 0
        for ch in text_upper:
            if ch in self.char_to_idx:
                final_chars.append(step2_chars[c_i])
                c_i += 1
            else:
                final_chars.append(ch)

        return "".join(final_chars), step1_text, step2_text, gamma

    def decrypt(self, ciphertext: str) -> str:
        """
        Расшифрование (обратный ход):
        1. Снятие гаммы: S[i] = (C[i] - G[i]) mod N
        2. Обратная подстановка: P[i] = (S[i] - K[i]) mod N
        """
        cipher_upper = ciphertext.upper()
        letters = [ch for ch in cipher_upper if ch in self.char_to_idx]
        key_len = len(self.key_word)
        gamma = self._generate_gamma(len(letters))

        # Снятие гаммы
        step1_chars = []
        for i, ch in enumerate(letters):
            c_val = self.char_to_idx[ch]
            g_val = gamma[i]
            s_val = (c_val - g_val) % self.n
            step1_chars.append(self.ALPHABET[s_val])

        # Обратная подстановка
        plain_chars = []
        for i, ch in enumerate(step1_chars):
            s_val = self.char_to_idx[ch]
            k_val = self.char_to_idx[self.key_word[i % key_len]]
            p_val = (s_val - k_val) % self.n
            plain_chars.append(self.ALPHABET[p_val])

        final_chars = []
        p_i = 0
        for ch in cipher_upper:
            if ch in self.char_to_idx:
                final_chars.append(plain_chars[p_i])
                p_i += 1
            else:
                final_chars.append(ch)

        return "".join(final_chars)


# ==============================================================================
# ЧАСТЬ 2. АЛГОРИТМ ПОТОКОВОГО ШИФРОВАНИЯ WAKE (РАЗДЕЛ 2.6.3 МЕТОДИЧКИ)
# ==============================================================================

class WAKECipher:
    """
    Алгоритм WAKE (Word Auto Key Encryption, Дэвид Уилер, 1993 г.).
    Раздел 2.6.3 методических указаний.
    Использует:
    - Блок замены S из 256 32-битных слов.
    - Регистры A, B, C, D.
    - Функцию перемешивания: M(x, y) = ((x + y) >> 8) ^ S[(x + y) & 255]
    - Режим CFB (Cipher Feedback).
    """
    def __init__(self, key_words: List[int] = None):
        if key_words is None or len(key_words) < 4:
            self.a0, self.b0, self.c0, self.d0 = 0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87654321
        else:
            self.a0, self.b0, self.c0, self.d0 = key_words[:4]

        # Инициализация S-блока из 256 32-битных слов
        self.s_box = [0] * 256
        self._init_s_box()

    def _init_s_box(self):
        """Псевдослучайная инициализация 256 32-битных слов таблицы подстановок S"""
        val = 0x31415926
        for i in range(256):
            val = (val * 1103515245 + 12345) & 0xFFFFFFFF
            # Старший байт - перестановка, младшие 3 байта - случайные
            self.s_box[i] = ((i << 24) | (val & 0x00FFFFFF)) & 0xFFFFFFFF

    def _m_func(self, x: int, y: int) -> int:
        """M(x, y) = ((x + y) >> 8) ^ S[(x + y) & 255]"""
        sum_xy = (x + y) & 0xFFFFFFFF
        low8 = sum_xy & 0xFF
        shifted = (sum_xy >> 8) & 0x00FFFFFF
        return (shifted ^ self.s_box[low8]) & 0xFFFFFFFF

    def encrypt_words(self, words: List[int]) -> List[int]:
        """Шифрование списка 32-битных слов в режиме обратной связи по шифротексту (CFB)"""
        a, b, c, d = self.a0, self.b0, self.c0, self.d0
        ciphertext_words = []

        for p in words:
            # Очередное слово гаммы k_i = d_i
            k_i = d
            c_word = (p ^ k_i) & 0xFFFFFFFF
            ciphertext_words.append(c_word)

            # Обновление регистров по шифротексту (режим CFB)
            # В алгоритме WAKE входной величиной шага выступает c_word
            a = self._m_func(a, c_word)
            b = self._m_func(b, a)
            c = self._m_func(c, b)
            d = self._m_func(d, c)

        return ciphertext_words

    def decrypt_words(self, cipher_words: List[int]) -> List[int]:
        """Дешифрование списка 32-битных слов"""
        a, b, c, d = self.a0, self.b0, self.c0, self.d0
        plain_words = []

        for c_word in cipher_words:
            k_i = d
            p_word = (c_word ^ k_i) & 0xFFFFFFFF
            plain_words.append(p_word)

            # Обновление регистров
            a = self._m_func(a, c_word)
            b = self._m_func(b, a)
            c = self._m_func(c, b)
            d = self._m_func(d, c)

        return plain_words


def run_variant_16():
    print("=" * 78)
    print("  ВАРИАНТ 16: «ШИФРОВАНИЕ АЛГОРИТМОМ»")
    print("=" * 78)

    # 1. Демонстрация комбинированного шифра Д. Френдберга (Раздел 2.7)
    print("\n--- 1. ОСНОВНАЯ РЕАЛИЗАЦИЯ: КОМБИНИРОВАННЫЙ ШИФР Д. ФРЕНДБЕРГА (Раздел 2.7) ---")
    plaintext = "ПРИКАЗ"
    key_sub = "КЛЮЧ"
    seed_prng = 555777

    cipher = FreindbergCipher(key_word=key_sub, prng_seed=seed_prng)
    cipher_text, step1, step2, gamma = cipher.encrypt(plaintext)

    print(f"[+] Исходный открытый текст:        '{plaintext}'")
    print(f"[+] Ключ подстановки (Виженер):      '{key_sub}'")
    print(f"[+] Зерно датчика гаммы (ЛКГ seed):  {seed_prng}")
    print(f"[+] Шаг 1 (после подстановки):       '{step1}'")
    print(f"[+] Выработанная гамма ПСЧ:          {gamma}")
    print(f"[+] Шаг 2 (итоговый шифртекст):      '{cipher_text}'")

    decrypted = cipher.decrypt(cipher_text)
    print(f"[+] Расшифрованный текст:            '{decrypted}'")
    assert decrypted == plaintext, "Ошибка: текст не совпал!"
    print("[OK] Тест комбинированного шифра Френдберга успешно пройден!\n")

    # 2. Демонстрация алгоритма WAKE (Раздел 2.6.3)
    print("--- 2. АЛГОРИТМ ПОТОКОВОГО ШИФРОВАНИЯ WAKE (Раздел 2.6.3) ---")
    # Переводим слово "ПРИКАЗ" в 32-битные слова
    test_words = [0x5052494B, 0x415A0001, 0xAABBCCDD]
    wake = WAKECipher()
    enc_words = wake.encrypt_words(test_words)
    dec_words = wake.decrypt_words(enc_words)

    print(f"[+] Исходные 32-битные блоки (HEX):  {['0x%08X' % w for w in test_words]}")
    print(f"[+] Зашифрованные блоки (HEX):       {['0x%08X' % w for w in enc_words]}")
    print(f"[+] Расшифрованные блоки (HEX):      {['0x%08X' % w for w in dec_words]}")
    assert test_words == dec_words, "Ошибка в алгоритме WAKE!"
    print("[OK] Тест алгоритма WAKE успешно пройден!")
    print("=" * 78)


if __name__ == "__main__":
    run_variant_16()
