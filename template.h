// Шифр ©2020-3 Глебов А.Н.
// Shifr ©2020-3 Glebe A.N.

# include "define.h"
# include <stdint.h>
# include "type.h"

# define  shifr_number_elt_copy( N ) shifr_number ## N ## _elt_copy

# define  shifr_number_dec_elt_copy(  N ) \
uint8_t shifr_number_elt_copy ( N ) ( shifr_number_type ( N ) const * np  , uint8_t i ) ;

# define  shifr_number_def_elt_copy( N ) \
uint8_t shifr_number_elt_copy ( N ) ( \
  shifr_number_type ( N ) const * const np  , uint8_t const i ) { \
  return  shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ i ] ; \
}

# define  shifr_number_dec_add( N ) \
  void  shifr_number_add  ( N ) ( shifr_number_type ( N ) * np  , \
    shifr_number_type ( N ) const * xp  ) ;

# define  shifr_number_def_add(  N , D ) \
void  shifr_number_add  ( N ) ( \
  shifr_number_type ( N ) * const restrict  np  , \
  shifr_number_type ( N ) const * const restrict  xp ) { \
  uint8_t per = 0 ; \
  uint8_t i = 0 ; \
  do  { \
    uint16_t const s = int_cast_uint16 ( \
      uint8_cast_uint16 ( shifr_number_elt_copy ( N ) ( np , i ) ) + \
      uint8_cast_uint16 ( shifr_number_elt_copy ( N ) ( xp , i ) ) + \
      uint8_cast_uint16 ( per ) ) ; \
    if ( s >= 0x100  ) {  \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] = \
        int_cast_uint8 ( s - 0x100 ) ; \
      per = 1 ; \
    } else  { \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] = \
        uint16_cast_uint8 ( s )  ;  \
      per = 0 ; \
    } \
    ++ i  ; \
  } while ( i < D ) ; \
}

# define  shifr_number_add( N ) shifr_number ## N ## _add

# include <stdbool.h>

# define  shifr_number_dec_not_zero(  N ) \
bool  shifr_number_not_zero ( N ) ( shifr_number_type ( N ) const * np  ) ;

# define  shifr_number_def_not_zero(  N , D ) \
bool  shifr_number_not_zero ( N ) ( \
  shifr_number_type ( N ) const * const np  ) { \
  uint8_t const * i = \
    & ( shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ; \
  do {  \
    --  i ; \
    if ( * i )  \
      return  true  ; \
  } while ( i not_eq & ( \
    shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ) ;  \
  return  false ; \
}

# define  shifr_number_not_zero( N ) shifr_number ## N ## _not_zero

# define  shifr_number_dec_dec(  N ) \
void  shifr_number_dec  ( N ) ( shifr_number_type ( N ) * np  ) ;

# define  shifr_number_def_dec(  N , D ) \
void  shifr_number_dec  ( N ) ( shifr_number_type ( N ) * const np  ) { \
  uint8_t  * i = & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ; \
  do {  \
    if ( ( * i ) == 0 ) \
      ( * i ) = 0xffU ; \
    else  { \
      -- ( * i ) ;  \
      break ; \
    } \
    ++  i ; \
  } while ( i not_eq & ( \
    shifr_number_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ) ; \
}

# define  shifr_number_dec( N ) shifr_number ## N ## _dec

# define  shifr_number_dec_div_mod(  N ) \
  uint8_t shifr_number_div_mod  ( N ) ( shifr_number_type ( N ) * np0 , uint8_t div ) ;

# define  shifr_number_def_div_mod(  N , D ) \
uint8_t shifr_number_div_mod  ( N ) ( \
  shifr_number_type ( N ) * const np0 , uint8_t const div ) { \
  shifr_number_priv_type ( N ) * const np = \
    shifr_number_pub_to_priv ( N ) ( np0 ) ; \
  uint8_t modi  = 0 ; \
  uint8_t i = D ; \
  do {  \
    -- i ;  \
    uint16_t const x = int_cast_uint16 ( ( uint8_cast_uint16 ( modi ) <<  8 ) \
      bitor uint8_cast_uint16 ( np -> arr [ i ] ) ) ; \
    modi  = int_cast_uint8 ( x % div ) ; \
    np -> arr [ i ] = int_cast_uint8 ( x / div ) ; \
  } while ( i > 0 ) ; \
  return  modi ; \
}

# define  shifr_number_div_mod( N ) shifr_number ## N ## _div_mod

# define  shifr_number_dec_set_byte(  N ) \
void  shifr_number_set_byte ( N ) ( shifr_number_type ( N ) * np0 , uint8_t x ) ;

# include <string.h> // memset

# define  shifr_number_def_set_byte(  N , D ) \
void  shifr_number_set_byte ( N ) ( shifr_number_type ( N ) * const np0 , \
  uint8_t const x ) { \
  shifr_number_priv_type ( N ) * const np = \
    shifr_number_pub_to_priv ( N ) ( np0 ) ; \
  memset  ( & ( np -> arr [ 1 ] ) , 0 , D - 1 ) ; \
  np -> arr [ 0 ] = x ; \
}

# define  shifr_number_set_byte( N ) shifr_number ## N ## _set_byte

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
  shifr_arrp shifrp , shifr_arrp deship ) ;

# define  shifr_password_load_def(  N , SDS ) \
void  shifr_password_load ( N ) ( \
  shifr_number_type ( N ) const * const password0 , \
  shifr_arrp const shifrp , shifr_arrp const deship ) { \
  shifr_initarr ( shifrp  , 0xff  , SDS ) ; \
  shifr_initarr ( deship  , 0xff  , SDS ) ; \
  uint8_t volatile  arrind  [ SDS ] ; \
  { uint8_t volatile  * arrj  = & ( arrind  [ SDS  ] ) ; \
    uint8_t j = SDS  ;  \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ; \
  } \
  uint8_t inde  = 0 ; \
  shifr_number_priv_type ( N ) password = \
    * shifr_number_const_pub_to_priv ( N ) ( password0 ) ; \
  do { \
    { uint8_t const cindex = shifr_number_div_mod ( N ) ( & password . pub ,  \
        int_cast_uint8 ( SDS - inde  ) ) ; \
      uint8_t volatile  * const arrind_cindexp = & ( arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( uint8volatilep_cast_unt8p ( arrind_cindexp ) , \
        uint8volatilep_cast_unt8p ( arrind_cindexp ) + 1 , \
        int_cast_size ( SDS  - inde  - cindex - 1 ) ) ; \
    } \
    ++ inde  ; \
  } while ( inde < SDS ) ; \
  shifr_memsetv ( arrind  , shifr_memsetv_default_byte , \
    sizeof  ( arrind  ) ) ; \
}

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
  shifr_arrp shifrp , shifr_arrp deship ) ;

# define  shifr_password_from_dice_def(  N , SDS ) \
void  shifr_password_from_dice  ( N ) ( \
  uint8_t const * const dice  , \
  shifr_arrp const shifrp , shifr_arrp const deship ) { \
  shifr_initarr ( shifrp  , 0xff  , SDS ) ; \
  shifr_initarr ( deship  , 0xff  , SDS ) ; \
  uint8_t volatile  arrind  [ SDS ] ; \
  { uint8_t volatile  * arrj  = & ( arrind  [ SDS  ] ) ; \
    uint8_t j = SDS  ; \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ; \
  } \
  uint8_t inde  = 0 ; \
  do { \
    { uint8_t const cindex  = \
        ( inde == SDS - 1 ? \
          0 : \
          dice  [ inde  ] ) ; \
      uint8_t volatile  * const arrind_cindexp = & ( arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( uint8volatilep_cast_unt8p ( arrind_cindexp ) ,  \
        uint8volatilep_cast_unt8p ( arrind_cindexp ) + 1 , \
        int_cast_size ( SDS  - inde  - cindex - 1 ) ) ; \
    } \
    ++ inde  ; \
  } while ( inde < SDS ) ; \
  shifr_memsetv ( arrind  , shifr_memsetv_default_byte ,  \
    sizeof  ( arrind  ) ) ; \
}
  
# define  shifr_number_def( N ) \
  struct  shifr_s_number ## N { \
    uint8_t _ ; \
  } ;

# define  shifr_password_to_string_templ( N ) \
  shifr_password  ##  N ##  _to_string_templ
  
# define  shifr_password_to_string_templ_dec( N ) \
void  shifr_password_to_string_templ  ( N ) ( \
  shifr_number_type ( N ) const * password0 , shifr_strvp string ,  \
  shifr_strp letters , uint8_t letterscount  ) ;

# define  shifr_string_to_password_templ( N ) \
  shifr_string_to_password  ##  N ##  _templ

# define  shifr_string_to_password_templ_dec( N ) \
void  shifr_string_to_password_templ  ( N ) ( t_ns_shifr * , \
  shifr_strvcp  string , shifr_number_type ( N ) * password , \
  shifr_strcp letters , uint8_t letterscount  ) ;

# ifdef SHIFR_DEBUG

# define  shifr_number_princ( N ) shifr_number  ##  N ##  _princ

# define  shifr_number_dec_princ( N ) \
void  shifr_number_princ  ( N ) ( shifr_number_type ( N ) const * np ,  \
  FILE * fs ) ;

# endif // SHIFR_DEBUG

# define  shifr_number_mul_byte( N ) shifr_number ## N ## _mul_byte

# define  shifr_number_dec_mul_byte(  N ) \
void  shifr_number_mul_byte ( N ) ( shifr_number_type ( N ) * , uint8_t )  ;

# define  shifr_number_set0( N ) shifr_number ## N ## _set0

# define  shifr_number_dec_set0( N ) \
  void shifr_number_set0( N )  ( shifr_number_type  ( N ) * ) ;
