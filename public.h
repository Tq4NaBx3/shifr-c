// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_PUBLIC_H
# define  SHIFR_PUBLIC_H

# include <stdio.h> // FILE
# include "define.h"
# include "type.h"

# define  shifr_number_dec_set0( N ) \
  void shifr_number ## N ## _set0  ( shifr_number_type  ( N ) * ) ;

# define  shifr_number_set0( N ) shifr_number ## N ## _set0
  
shifr_number_dec_set0 ( v2 )
shifr_number_dec_set0 ( v3 )

# define  shifr_number_dec_mul_byte(  N ) \
void  shifr_number ## N ## _mul_byte ( shifr_number_type ( N ) * , uint8_t )  ;

# define  shifr_number_mul_byte( N ) shifr_number ## N ## _mul_byte

shifr_number_dec_mul_byte ( v2 )
shifr_number_dec_mul_byte ( v3 )

# ifdef SHIFR_DEBUG

# define  shifr_number_dec_princ( N ) \
void  shifr_number ## N ## _princ ( shifr_number_type ( N ) const * np ,  \
  FILE * fs ) ;

# define  shifr_number_princ( N ) shifr_number  ##  N ##  _princ

shifr_number_dec_princ  ( v2 )
shifr_number_dec_princ  ( v3 )

void  shifr_printarr  ( shifr_strcp name , shifr_arrcp p , size_t arrsize , FILE * f ) ;

# endif // SHIFR_DEBUG

# define  shifr_string_to_password_templ_dec( N ) \
void  shifr_string_to_password  ##  N ##  _templ ( t_ns_shifr * , shifr_strvcp  string , \
  shifr_number_type ( N ) * password , shifr_strcp letters , uint8_t letterscount  ) ;

shifr_string_to_password_templ_dec  ( v2 )
shifr_string_to_password_templ_dec  ( v3 )

# define  shifr_string_to_password_templ( N ) shifr_string_to_password  ##  N ##  _templ

# define  shifr_password_to_string_templ_dec( N ) \
void  shifr_password  ##  N ##  _to_string_templ ( \
  shifr_number_type ( N ) const * password0 , shifr_strvp string ,  \
  shifr_strp letters , uint8_t letterscount  ) ;

shifr_password_to_string_templ_dec  ( v2 )
shifr_password_to_string_templ_dec  ( v3 )  

# define  shifr_password_to_string_templ( N ) shifr_password  ##  N ##  _to_string_templ

// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass2 ( t_ns_shifr * ) ;

// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass3 ( t_ns_shifr * ) ;

// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 = 0 .. 16!-1
void  shifr_pass_to_array2 ( t_ns_shifr * ) ;

// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 0 .. 64!-1
void  shifr_pass_to_array3 ( t_ns_shifr * ) ;

// Disable ping and input buffering
// Отключить эхо-вывод и буферизацию ввода
void shifr_set_keypress ( t_ns_shifr * ) ;

// Console recovery of default state
// Восстановление дефолтного состояния консоли
void shifr_reset_keypress ( t_ns_shifr * ) ;

/*
 Translation of the internal password '-> raspr. pass' 
to the encryption table '-> shifr', decryption '-> deshi'
 Перевод внутреннего пароля '-> raspr  . pass' в таблицы шифрования '-> shifr' ,
дешифровки '-> deshi'
*/
void  shifr_password_load_uni ( t_ns_shifr * ) ;

/*
Password translation by letters '-> password_letters' to internal '-> raspr. pass'
Перевод  пароля буквами '-> password_letters' во внутренний '-> raspr  . pass'
*/
void  shifr_string_to_password ( t_ns_shifr * ) ;

/*
Translation of the internal password '-> raspr. pass' to letters '-> password_letters'
Перевод внутреннего пароля '-> raspr  . pass ' в буквы '->password_letters'
*/
void  shifr_password_to_string  ( t_ns_shifr * ) ;

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
shifr_size_io shifr_encrypt2  ( t_ns_shifr * , shifr_arrcps input , shifr_arrps output )  ;
shifr_size_io shifr_encrypt3  ( t_ns_shifr * , shifr_arrcps input , shifr_arrps output )  ;
  
/*
Finished buffer encryption, returns output_buffer size written
Заканчивает шифрование буфера, возвращает размер записаных данных.
*/
size_t  shifr_encrypt2_flush  ( t_ns_shifr * , shifr_arrps output )  ;

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
shifr_size_io  shifr_decrypt2 ( t_ns_shifr * , shifr_arrcps input , shifr_arrps output ) ;
  
/*
Decryption
Расшифровка
*/
shifr_size_io  shifr_decrypt3 ( t_ns_shifr * , shifr_arrcps input , shifr_arrps output ) ;

uint8_t  shifr_streambuf_writeflushzero3 ( t_ns_shifr * , shifr_arrps ) ;

enum  { shifr_memsetv_default_byte  = 0x55  } ;

void volatile * shifr_memsetv ( void volatile * str , uint8_t ch , size_t n ) ;

void  shifr_destr ( t_ns_shifr * ) ;

# endif // SHIFR_PUBLIC_H
