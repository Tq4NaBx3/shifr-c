// Шифр ©2020-3 Глебов А.Н.
// Shifr ©2020-3 Glebe A.N.

# ifndef  SHIFR_PUBLIC_H
# define  SHIFR_PUBLIC_H

# include <stdio.h> // FILE
# include "define.h"
# include "type.h"
  
# ifdef SHIFR_DEBUG

# define  shifr_number_princ( N ) shifr_number_  ##  N ##  _princ

# define  shifr_number_dec_princ( N ) \
void  shifr_number_princ  ( N ) ( shifr_number_type ( N ) const * np , FILE * fs ) ;

shifr_number_dec_princ  ( v2 )
shifr_number_dec_princ  ( v3 )

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

# define  shifr_number_elt_copy( N ) shifr_number_ ## N ## _elt_copy

# define  shifr_number_dec_elt_copy(  N ) \
uint8_t shifr_number_elt_copy ( N ) ( shifr_number_type ( N ) const * np  , uint8_t i ) ;

inline  shifr_number_dec_elt_copy ( v2  )
inline  shifr_number_dec_elt_copy ( v3  )

# define  shifr_number_add( N ) shifr_number_ ## N ## _add

# define  shifr_number_dec_add( N ) \
  void  shifr_number_add  ( N ) ( shifr_number_type ( N ) * np  , \
    shifr_number_type ( N ) const * xp  ) ;

shifr_number_dec_add  ( v2  )
shifr_number_dec_add  ( v3  )

# define  shifr_number_not_zero( N ) shifr_number_ ## N ## _not_zero

# define  shifr_number_dec_not_zero(  N ) \
bool  shifr_number_not_zero ( N ) ( shifr_number_type ( N ) const * np  ) ;

# include <stdbool.h>

shifr_number_dec_not_zero ( v2  )
shifr_number_dec_not_zero ( v3  )

# define  shifr_number_dec( N ) shifr_number_ ## N ## _dec

# define  shifr_number_dec_dec(  N ) \
void  shifr_number_dec  ( N ) ( shifr_number_type ( N ) * np  ) ;

shifr_number_dec_dec  ( v2  )
shifr_number_dec_dec  ( v3  )

# define  shifr_number_div_mod( N ) shifr_number_ ## N ## _div_mod

# define  shifr_number_dec_div_mod(  N ) \
  uint8_t shifr_number_div_mod  ( N ) ( shifr_number_type ( N ) * np0 , uint8_t div ) ;

shifr_number_dec_div_mod  ( v2  )
shifr_number_dec_div_mod  ( v3  )

# define  shifr_number_set_byte( N ) shifr_number_ ## N ## _set_byte

# define  shifr_number_dec_set_byte(  N ) \
void  shifr_number_set_byte ( N ) ( shifr_number_type ( N ) * np0 , uint8_t x ) ;

shifr_number_dec_set_byte ( v2  )
shifr_number_dec_set_byte ( v3  )

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

# include <stdint.h> // uint16_t

# define  uint8_cast_uint16 shifr_uint8_cast_uint16
inline  uint16_t  uint8_cast_uint16 ( uint8_t ) ;

# define  uint8_cast_uint shifr_uint8_cast_uint
inline  unsigned int  uint8_cast_uint ( uint8_t ) ;

# define  uint16_cast_uint8 shifr_uint16_cast_uint8
inline  uint8_t  uint16_cast_uint8 ( uint16_t ) ;

# define  int_cast_uint8 shifr_int_cast_uint8
inline  uint8_t  int_cast_uint8 ( int ) ;

# define  uint_cast_uint8 shifr_uint_cast_uint8
inline  uint8_t  uint_cast_uint8 ( unsigned  int ) ;

# define  int_cast_uint16 shifr_int_cast_uint16
inline  uint16_t  int_cast_uint16 ( int ) ;

# define  uint_cast_uint16 shifr_uint_cast_uint16
inline  uint16_t  uint_cast_uint16 ( unsigned int ) ;

# define  int_cast_size shifr_int_cast_size
inline  size_t  int_cast_size ( int ) ;

# define  int_cast_uint shifr_int_cast_uint
inline  unsigned  int int_cast_uint ( int ) ;

# define  char_cast_uint8 shifr_char_cast_uint8
inline  uint8_t  char_cast_uint8 ( char ) ;

# define  uint8_cast_char shifr_uint8_cast_char
inline  char  uint8_cast_char ( uint8_t ) ;

# define  uint16_cast_char shifr_uint16_cast_char
inline  char  uint16_cast_char ( uint16_t ) ;

# define  int_cast_char shifr_int_cast_char
inline  char  int_cast_char ( int ) ;

# define  charvolatilep_cast_charp shifr_charvolatilep_cast_charp
inline  char * charvolatilep_cast_charp ( char volatile * ) ;

# define  uint8volatilep_cast_unt8p shifr_uint8volatilep_cast_unt8p
inline  uint8_t * uint8volatilep_cast_unt8p ( uint8_t volatile * ) ;

# define  charconstp_cast_stringconstp shifr_charconstp_cast_stringconstp
inline  shifr_strcp charconstp_cast_stringconstp ( char const * ) ;

# define  lint_cast_ulint shifr_lint_cast_ulint
inline  unsigned  long  int lint_cast_ulint ( long  int ) ;

# define  ulint_cast_uint shifr_ulint_cast_uint
inline  unsigned int ulint_cast_uint ( unsigned long  int ) ;

# define  ulint_cast_lint shifr_ulint_cast_lint
inline  long int ulint_cast_lint ( unsigned long  int ) ;

# endif // SHIFR_PUBLIC_H
