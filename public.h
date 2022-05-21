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

void  shifr_printarr  ( shifr_strcp name , shifr_arrcp p , size_t arrsize , FILE * f ) ;

# endif // SHIFR_DEBUG

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

void  shifr_destr ( t_ns_shifr * ) ;

uint8_t shifr_flush ( t_ns_shifr  * , shifr_arrps ) ;

# endif // SHIFR_PUBLIC_H
