// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_PUBLIC_H
# define  SHIFR_PUBLIC_H

# include <stdio.h> // FILE
# include "define.h"
# include "type.h"
  
# ifdef SHIFR_DEBUG

shifr_number_dec_princ  ( v2 )
shifr_number_dec_princ  ( v3 )

void  shifr_printarr  ( shifr_strcp name , shifr_arrcp p , size_t arrsize ,
  FILE * f ) ;

# endif // SHIFR_DEBUG

/*
'password_letters' as string to 'raspr.pass' as big number
Перевод  пароля буквами 'password_letters' в большое число 'raspr.pass'
 + shifr_password_load_uni
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

void  shifr_sole_init ( t_ns_shifr  * ) ;

# endif // SHIFR_PUBLIC_H
