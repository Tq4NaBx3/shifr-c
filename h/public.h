// Shifr ©2020-3 Glebe A.N. public
// Шифр ©2020-3 Глебов А.Н. публичные

# ifndef  SHIFR_PUBLIC_H
# define  SHIFR_PUBLIC_H

# include "define.h"
# include "type.h"
# include <stdlib.h> // size_t
# include <stdio.h> // FILE
  
# ifdef SHIFR_DEBUG

void  shifr_printarr  ( shifr_strcp name , shifr_arrcp p , size_t arrsize , FILE * f ) ;

# endif // SHIFR_DEBUG

/*
copying the password string + 'password_letters' as string to 'raspr.pass' as big number
 + tables shifr deshi
копирование строки пароля + перевод  пароля буквами 'password_letters' в большое число 'raspr.pass'
 + таблицы shifr deshi
*/
void  shifr_password_set_by_string ( t_ns_shifr * , char const * ) ;
  
/*
'password_letters' as string to 'raspr.pass' as big number
 + tables shifr deshi
Перевод  пароля буквами 'password_letters' в большое число 'raspr.pass'
 + таблицы shifr deshi
*/
void  shifr_string_to_password ( t_ns_shifr * ) ;

/*
Translation of the big number 'raspr.pass' to string 'password_letters'
Перевод большого числа 'raspr.pass ' в строку 'password_letters'

 0 - ''
 1 - '0' , 2 - '1'
 3 - '00' , 4 - '01' , 5 - '10' , 6 - '11'
*/
void  shifr_password_to_string  ( t_ns_shifr * ) ;

void  shifr_destr ( t_ns_shifr * ) ;

uint8_t shifr_flush ( t_ns_shifr  * , shifr_arrps ) ;

void  shifr_salt_init ( t_ns_shifr  * ) ;

/*
пароль раскладываем в таблицу шифровки , дешифровки
  пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  пароль делим на 16, остаются 15! вариантов пароля
пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
секретных кодов для соли+данных 0x1
в deshi нужна соль

we lay out the password in the table of encryption, decryption
password % 0x10 = 0xa means that 0xa is the encrypted code for salt + data 0x0
divide the password by 16, 15! remain password options
password % 0xf = 0xa is the sequence number for the remaining NOT occupied from
0xff secret codes for salt + data 0x1
deshi needs salt
*/
# define  shifr_password_load( N ) shifr_password_  ##  N ##  _load

# define  shifr_password_load_dec(  N ) \
void  shifr_password_load ( N ) ( shifr_number_type ( N ) const * password0 , \
  shifr_arrvp shifrp , shifr_arrvp  deship ) ;

# include "number/type.h"

shifr_password_load_dec ( v2  )
shifr_password_load_dec ( v3  )

/*
пароль раскладываем в таблицу шифровки , дешифровки
  пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  пароль делим на 16, остаются 15! вариантов пароля
пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
секретных кодов для соли+данных 0x1
в deshi нужна соль

we lay out the password in the table of encryption, decryption
password % 0x10 = 0xa means that 0xa is the encrypted code for salt + data 0x0
divide the password by 16, 15! remain password options
password % 0xf = 0xa is the sequence number for the remaining NOT occupied from
0xff secret codes for salt + data 0x1
deshi needs salt
*/
# define  shifr_password_from_dice( N ) shifr_password_  ##  N ##  _from_dice

# define  shifr_password_from_dice_dec(  N ) \
void  shifr_password_from_dice  ( N ) ( uint8_t const * dice  , \
  shifr_arrvp shifrp , shifr_arrvp  deship ) ;

shifr_password_from_dice_dec (  v2  )
shifr_password_from_dice_dec (  v3  )

// generate big number as password to raspr.pass
//  + create tables shifr deshi
void  shifr_generate_password ( t_ns_shifr * )  ;

// from stdin get password string -> make big number -> tables shifr deshi
void  shifr_enter_password ( t_ns_shifr * ) ;

void  shifr_init  ( t_ns_shifr  * ) ;

# ifdef SHIFR_DEBUG
shifr_timestamp_t get_timestamp ( void )  ;
# endif

int shifr_show_help ( t_ns_shifr  const * ) ;

// generate big number as password, convert to string and puts
// in debug mode creates tables shifr deshi many times
void  shifr_main_genpsw ( t_ns_shifr  * ) ;

void  shifr_test_password ( t_ns_shifr  * , size_t nr  ) ;

# define  shifr_encode_file(  N ) shifr_encode_file_  ##  N

# define  shifr_encode_file_dec(  N ) \
void  shifr_encode_file ( N ) ( t_ns_shifr  * , \
  uint8_t ( * inputbufferp  ) [ ] , size_t  inputbuffersize , \
  uint8_t ( * outputbufferp ) [ ] , size_t  outputbuffersize  ) ;

shifr_encode_file_dec (  v2 )
shifr_encode_file_dec (  v3 )

# define  shifr_decode_file(  N ) shifr_decode_file_  ##  N

# define  shifr_decode_file_dec(  N ) \
void  shifr_decode_file ( N ) ( t_ns_shifr  * , \
  uint8_t ( * inputbufferp  ) [ ] , size_t  inputbuffersize , \
  uint8_t ( * outputbufferp ) [ ] , size_t  outputbuffersize  ) ;

shifr_decode_file_dec (  v2 )
shifr_decode_file_dec (  v3 )

/*
Encryption
Reads data from 'input.cp' of size 'input.s' bytes,
writes to 'output.p' of size 'output.s' bytes,
returns the size of read and written data
Шифрование
Читает данные из 'input.cp' размера 'input.s' байт ,
записывает в 'output.p' размера 'output.s' байт ,
возвращает размер считаных и записаных данных
*/
# define  shifr_encrypt( N ) shifr_encrypt_  ##  N

# define  shifr_encrypt_dec( N ) \
shifr_size_io  shifr_encrypt ( N ) ( t_ns_shifr * , shifr_arrcps input , \
  shifr_arrps output )  ;

shifr_encrypt_dec ( v2 )
shifr_encrypt_dec ( v3 )

/*
Decryption
Reads data from 'input.cp' of size 'input.s' bytes,
writes to 'output.p' of size 'output.s' bytes,
returns the size of read and written data
Расшифровка
Читает данные из 'input.cp' размера 'input.s' байт ,
записывает в 'output.p' размера 'output.s' байт ,
возвращает размер считаных и записаных данных
*/
# define  shifr_decrypt( N ) shifr_decrypt_  ##  N

# define  shifr_decrypt_dec( N ) \
shifr_size_io  shifr_decrypt ( N ) ( t_ns_shifr * , shifr_arrcps input , \
  shifr_arrps output )  ;

shifr_decrypt_dec ( v2 )
shifr_decrypt_dec ( v3 )

extern  char  const shifr_base64_num_to_let [ 0x40  ] ;

extern  unsigned  int const shifr_base64_let_to_num [ ] ;

# endif // SHIFR_PUBLIC_H
