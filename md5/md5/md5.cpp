// md5.cpp: определяет точку входа для консольного приложения.
//
#include "stdafx.h"
#include <iostream>
#include <math.h>
#include "md5.h"

typedef unsigned int uint; //вместо int используем uint

uint F(uint X, uint Y, uint Z) { return ((X & Y) | ((~X) & Z)); }
uint G(uint X, uint Y, uint Z) { return (X & Z) | (Y & (~Z)); }
uint H(uint X, uint Y, uint Z) { return X ^ Y ^ Z; }
uint I(uint X, uint Y, uint Z) { return Y ^ (X | (~Z)); }
uint rotate_left(uint value, int shift) { return value << shift | value >> (32 - shift); }

/*
Функция to_hex перегоняет в hex, полученное на входе, значение. 
Принцип работы аналогичен элементарному переводу из dec в bin: число делим на 256. 
Нам надо получить dec-значение сразу 2ух символов. 
Получаем остаток от деления на 256 и приводим его (остаток) в hex. 
И так до тех пор, пока входное значение нельзя будет нацело поделить на 256.
*/


std::string to_hex(uint value)
{
	std::string out;
	unsigned char hex;
	char hex_res[3];
	while (value)
	{
		hex = value % 256;
		_itoa_s(hex, hex_res, 16);
		if (hex_res[1] == '\0')
		{
			hex_res[1] = hex_res[0];
			hex_res[0] = '0';
			hex_res[2] = '\0';
		}
		out.append(hex_res); //добавляем в конец
		value /= 256;
	}
	return out;
}

std::string get_md5(std::string in)
{
							//Шаг 1.
	int length = in.length(); //получаем длину входного сообщения
	int rest = length % 64; //остаток от деления на 64байта
	int size = 0; //тут будет храниться размер сообщения после первых 2ух шагов.

	if (rest < 56) //если остаток от деления на 64 меньше 56
		size = length - rest + 56 + 8; //подгоняем размер так, что бы он был кратен 64(+8 байт для 2ого шага).
	else
		size = length + 64 - rest + 56 + 8; //подгоняем размер так, что бы он был кратен 64(+8 байт для 2ого шага).

	unsigned char *msg_for_decode = new unsigned char[size]; //создаем динамический массив для хранения сообщения, которое далее будет кодироваться

	for (int i = 0; i < length; i++) //первые length элементов сIn
		msg_for_decode[i] = in[i]; //заполняем символами входного сообщения
	msg_for_decode[length] = 0x80; //ставим в конец сообщения единичный бит.
	for (int i = length + 1; i < size; i++)  //а все остальное
		msg_for_decode[i] = 0; //заполняем нулями


							   //Шаг 2.
	__int64 bit_length = (uint)(length)* 8;  //длина сообщения в битах.

	for (int i = 0; i < 8; i++)  //последние 8 байт
		msg_for_decode[size - 8 + i] = (unsigned char)(bit_length >> i * 8);//заполняем 64-битным представлением длины данных до выравнивания

									//Шаг 3.
	uint A = 0x67452301, B = 0xefcdab89, C = 0x98badcfe, D = 0x10325476; //Инициализируем начальные значения регистров.
	uint T[64];//64-элементная таблица данных (констант).

	for (int i = 0;i<64;i++) //всю таблицу констант
		T[i] = uint(pow(2, 32)*fabs(sin(i + 1))); //заполняем в соответствии с алгоритмом.

	//объявляем массив Х, в котором будет 32-разрядное представление сообщения.
	uint *X = (uint*)(msg_for_decode); //загоняем в массив Х сообщение msg_for_decode.

									   //Шаг 4.
	uint AA = 0, BB = 0, CC = 0, DD = 0;

	for (int i = 0; i < size / 4; i += 16) {
		AA = A;BB = B; CC = C; DD = D;

		//раунд 1
		A = B + rotate_left((A + F(B, C, D) + X[i + 0] + T[0]), 7);
		D = A + rotate_left((D + F(A, B, C) + X[i + 1] + T[1]), 12);
		C = D + rotate_left((C + F(D, A, B) + X[i + 2] + T[2]), 17);
		B = C + rotate_left((B + F(C, D, A) + X[i + 3] + T[3]), 22);

		A = B + rotate_left((A + F(B, C, D) + X[i + 4] + T[4]), 7);
		D = A + rotate_left((D + F(A, B, C) + X[i + 5] + T[5]), 12);
		C = D + rotate_left((C + F(D, A, B) + X[i + 6] + T[6]), 17);
		B = C + rotate_left((B + F(C, D, A) + X[i + 7] + T[7]), 22);

		A = B + rotate_left((A + F(B, C, D) + X[i + 8] + T[8]), 7);
		D = A + rotate_left((D + F(A, B, C) + X[i + 9] + T[9]), 12);
		C = D + rotate_left((C + F(D, A, B) + X[i + 10] + T[10]), 17);
		B = C + rotate_left((B + F(C, D, A) + X[i + 11] + T[11]), 22);

		A = B + rotate_left((A + F(B, C, D) + X[i + 12] + T[12]), 7);
		D = A + rotate_left((D + F(A, B, C) + X[i + 13] + T[13]), 12);
		C = D + rotate_left((C + F(D, A, B) + X[i + 14] + T[14]), 17);
		B = C + rotate_left((B + F(C, D, A) + X[i + 15] + T[15]), 22);

		//раунд 2
		A = B + rotate_left((A + G(B, C, D) + X[i + 1] + T[16]), 5);
		D = A + rotate_left((D + G(A, B, C) + X[i + 6] + T[17]), 9);
		C = D + rotate_left((C + G(D, A, B) + X[i + 11] + T[18]), 14);
		B = C + rotate_left((B + G(C, D, A) + X[i + 0] + T[19]), 20);

		A = B + rotate_left((A + G(B, C, D) + X[i + 5] + T[20]), 5);
		D = A + rotate_left((D + G(A, B, C) + X[i + 10] + T[21]), 9);
		C = D + rotate_left((C + G(D, A, B) + X[i + 15] + T[22]), 14);
		B = C + rotate_left((B + G(C, D, A) + X[i + 4] + T[23]), 20);

		A = B + rotate_left((A + G(B, C, D) + X[i + 9] + T[24]), 5);
		D = A + rotate_left((D + G(A, B, C) + X[i + 14] + T[25]), 9);
		C = D + rotate_left((C + G(D, A, B) + X[i + 3] + T[26]), 14);
		B = C + rotate_left((B + G(C, D, A) + X[i + 8] + T[27]), 20);

		A = B + rotate_left((A + G(B, C, D) + X[i + 13] + T[28]), 5);
		D = A + rotate_left((D + G(A, B, C) + X[i + 2] + T[29]), 9);
		C = D + rotate_left((C + G(D, A, B) + X[i + 7] + T[30]), 14);
		B = C + rotate_left((B + G(C, D, A) + X[i + 12] + T[31]), 20);

		//раунд 3
		A = B + rotate_left((A + H(B, C, D) + X[i + 5] + T[32]), 4);
		D = A + rotate_left((D + H(A, B, C) + X[i + 8] + T[33]), 11);
		C = D + rotate_left((C + H(D, A, B) + X[i + 11] + T[34]), 16);
		B = C + rotate_left((B + H(C, D, A) + X[i + 14] + T[35]), 23);

		A = B + rotate_left((A + H(B, C, D) + X[i + 1] + T[36]), 4);
		D = A + rotate_left((D + H(A, B, C) + X[i + 4] + T[37]), 11);
		C = D + rotate_left((C + H(D, A, B) + X[i + 7] + T[38]), 16);
		B = C + rotate_left((B + H(C, D, A) + X[i + 10] + T[39]), 23);

		A = B + rotate_left((A + H(B, C, D) + X[i + 13] + T[40]), 4);
		D = A + rotate_left((D + H(A, B, C) + X[i + 0] + T[41]), 11);
		C = D + rotate_left((C + H(D, A, B) + X[i + 3] + T[42]), 16);
		B = C + rotate_left((B + H(C, D, A) + X[i + 6] + T[43]), 23);

		A = B + rotate_left((A + H(B, C, D) + X[i + 9] + T[44]), 4);
		D = A + rotate_left((D + H(A, B, C) + X[i + 12] + T[45]), 11);
		C = D + rotate_left((C + H(D, A, B) + X[i + 15] + T[46]), 16);
		B = C + rotate_left((B + H(C, D, A) + X[i + 2] + T[47]), 23);

		//раунд 4
		A = B + rotate_left((A + I(B, C, D) + X[i + 0] + T[48]), 6);
		D = A + rotate_left((D + I(A, B, C) + X[i + 7] + T[49]), 10);
		C = D + rotate_left((C + I(D, A, B) + X[i + 14] + T[50]), 15);
		B = C + rotate_left((B + I(C, D, A) + X[i + 5] + T[51]), 21);

		A = B + rotate_left((A + I(B, C, D) + X[i + 12] + T[52]), 6);
		D = A + rotate_left((D + I(A, B, C) + X[i + 3] + T[53]), 10);
		C = D + rotate_left((C + I(D, A, B) + X[i + 10] + T[54]), 15);
		B = C + rotate_left((B + I(C, D, A) + X[i + 1] + T[55]), 21);

		A = B + rotate_left((A + I(B, C, D) + X[i + 8] + T[56]), 6);
		D = A + rotate_left((D + I(A, B, C) + X[i + 15] + T[57]), 10);
		C = D + rotate_left((C + I(D, A, B) + X[i + 6] + T[58]), 15);
		B = C + rotate_left((B + I(C, D, A) + X[i + 13] + T[59]), 21);

		A = B + rotate_left((A + I(B, C, D) + X[i + 4] + T[60]), 6);
		D = A + rotate_left((D + I(A, B, C) + X[i + 11] + T[61]), 10);
		C = D + rotate_left((C + I(D, A, B) + X[i + 2] + T[62]), 15);
		B = C + rotate_left((B + I(C, D, A) + X[i + 9] + T[63]), 21);

		A += AA;
		B += BB;
		C += CC;
		D += DD;
	}

	delete[]msg_for_decode; //освобождаем память
	std::string res = to_hex(A) + to_hex(B) + to_hex(C) + to_hex(D); //заполняем выходную строку hex-//представлением, полученных в шаге 4, регистров
	return res; //выводим результат
}


int main()
{
	char *r = new char;
	setlocale(LC_ALL, "rus");
	std::cout << "Введите слово где кэширования " << std::endl;
	std::cin >> r;
	std::cout << "Кэш MD5" << std::endl;
	std::cout << get_md5(r) << std::endl;
	std::cout << std::endl;
	std::cout << "Выводим Кэш MD5 пустой строки: " << get_md5("") << std::endl;

    return 0;
}

