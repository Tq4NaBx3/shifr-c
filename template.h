// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# include "define.h"

# define  shifr_number_def_set0( N , D ) \
  void shifr_number ## N ## _set0  ( shifr_number_type  ( N ) * const np ) { \
    memset  ( & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) , 0 ,  \
      D ) ; }

# define  shifr_number_def_mul_byte(  N , D ) \
void  shifr_number ## N ## _mul_byte ( shifr_number_type ( N ) * const np  , \
  uint8_t const byte ) {  \
  if ( byte == 0 ) {  \
    shifr_number_set0 ( N ) ( np ) ; \
    return  ; } \
  if ( byte == 1 )  \
    return ; \
  uint8_t per = 0 ; \
  { uint8_t i = 0 ; \
    do { \
      uint16_t const x = ( uint16_t ) ( ( ( uint16_t  ) ( \
        shifr_number_elt_copy ( N ) ( np , i ) ) ) * \
        ( ( uint16_t  ) byte  ) + ( ( uint16_t  ) per ) ) ; \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] =  \
        ( uint8_t ) ( x bitand 0xff ) ; \
      per = ( uint8_t ) ( x >>  8 ) ; \
      ++  i ; \
    } while ( i < D ) ; } }
    
# define  shifr_password_to_string_templ_def( N ) \
void  shifr_password  ##  N ##  _to_string_templ ( \
  shifr_number_type ( N ) const * const password0 , shifr_strvp const string , \
  shifr_strp letters , uint8_t const letterscount  ) { \
  char  volatile  * stringi = & ( ( * string )  [ 0 ] ) ; \
  if ( shifr_number_not_zero  ( N ) ( password0 ) ) { \
    shifr_number_priv_type ( N ) password = * shifr_number_const_pub_to_priv ( N ) ( \
      password0 ) ; \
    do {  \
      /* здесь предыдущие размеры заняли место паролей */ \
      shifr_number_dec ( N ) ( & password . pub ) ;  \
      ( * stringi ) = ( * letters ) [ \
        shifr_number_div_mod ( N ) ( & password . pub , letterscount ) ] ;  \
      ++  stringi ; \
    } while ( shifr_number_not_zero ( N ) ( & password . pub ) ) ; }  \
  ( * stringi ) = '\00' ; }

# define  shifr_string_to_password_templ_def( N ) \
void  shifr_string_to_password  ##  N ##  _templ (  \
  t_ns_shifr * const ns_shifrp , shifr_strvcp  const string  ,  \
  shifr_number_type ( N ) * const password , shifr_strcp const letters ,  \
  uint8_t const letterscount  ) { \
  char  volatile  const * restrict stringi = & ( ( * string )  [ 0 ] ) ; \
  if  ( ( * stringi ) == '\00' ) { \
    shifr_number_set0 ( N ) ( password ) ; \
    return ; } \
  shifr_number_priv_type ( N ) pass ; \
  shifr_number_set0 ( N ) ( & pass . pub ) ; \
  shifr_number_priv_type ( N ) mult ;  \
  shifr_number_set_byte ( N ) ( & mult . pub , 1 ) ;  \
  do  { \
    uint8_t i = letterscount ;  \
    do {  \
      -- i ;  \
      if ( ( * stringi ) == ( * letters ) [ i ] ) \
        goto found ; \
    } while ( i ) ; \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?  \
      ( shifr_strcp ) & u8"неправильная буква в пароле" : \
      ( shifr_strcp ) & "wrong letter in password" ) ;  \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
found : ; \
    { shifr_number_priv_type ( N ) tmp = mult ;  \
      shifr_number_mul_byte ( N ) ( & tmp . pub , ( uint8_t ) ( i + 1 ) ) ; \
      shifr_number_add ( N ) ( &  pass . pub , & tmp . pub )  ; }  \
    shifr_number_mul_byte ( N ) ( & mult . pub , letterscount ) ; \
    ++  stringi ; \
  } while ( ( * stringi ) not_eq '\00' ) ;  \
  ( * shifr_number_pub_to_priv ( N ) ( password  ) ) = pass ; }

# ifdef SHIFR_DEBUG

# define  shifr_number_def_princ( N , D ) \
void  shifr_number  ##  N ##  _princ ( shifr_number_type ( N ) const * const np , \
  FILE * const fs ) { \
  fputs ( "[ " , fs ) ; \
  uint8_t i = D ;  \
  do {  \
    -- i ;  \
    fprintf ( fs  , "%x , " , shifr_number_elt_copy ( N ) ( np , i ) ) ; \
  } while ( i ) ; \
  fputs ( "]" , fs ) ; }

# endif // SHIFR_DEBUG

# define  shifr_number_def_elt_copy( N ) \
uint8_t shifr_number ## N ## _elt_copy  ( \
  shifr_number_type ( N ) const * const np  , uint8_t const i ) { \
  return  shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ i ] ; }

# define  shifr_number_elt_copy( N ) shifr_number ## N ## _elt_copy

# define  shifr_number_def_add(  N , D ) \
void  shifr_number ## N ## _add  ( shifr_number_type ( N ) * const restrict  np  , \
  shifr_number_type ( N ) const * const restrict  xp ) {  \
  uint8_t per = 0 ; \
  uint8_t i = 0 ; \
  do  { \
    uint16_t const s = ( uint16_t  ) ( ( ( uint16_t  ) (  \
      shifr_number_elt_copy ( N ) ( np , i ) ) ) + \
      ( ( uint16_t  ) shifr_number_elt_copy ( N ) ( xp , i ) ) + \
      ( ( uint16_t  ) per ) ) ; \
    if ( s >= 0x100  ) {  \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] = ( uint8_t ) ( s - 0x100 ) ; \
      per = 1 ; } \
    else  { \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] = ( uint8_t ) s  ;  \
      per = 0 ;  }  \
    ++ i  ; \
  } while ( i < D ) ; }

# define  shifr_number_add( N ) shifr_number ## N ## _add

# define  shifr_number_def_not_zero(  N , D ) \
bool  shifr_number ## N ## _not_zero  ( \
  shifr_number_type ( N ) const * const np  ) { \
  uint8_t const * i = & ( shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ; \
  do {  \
    --  i ; \
    if ( * i )  \
      return  true  ; \
  } while ( i not_eq & ( shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ) ;  \
  return  false ; }

# define  shifr_number_not_zero( N ) shifr_number ## N ## _not_zero

# define  shifr_number_def_dec(  N , D ) \
void  shifr_number ## N ## _dec ( shifr_number_type ( N ) * const np  ) { \
  uint8_t  * i = & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ; \
  do {  \
    if ( ( * i ) == 0 ) \
      ( * i ) = 0xffU ; \
    else  { \
      -- ( * i ) ;  \
      break ; } \
    ++  i ; \
  } while ( i not_eq & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ) ; }

# define  shifr_number_dec( N ) shifr_number ## N ## _dec

# define  shifr_number_def_div_mod(  N , D ) \
uint8_t shifr_number ## N ## _div_mod ( \
  shifr_number_type ( N ) * const np0 , uint8_t const div ) { \
  shifr_number_priv_type ( N ) * const np = shifr_number_pub_to_priv ( N ) ( np0 ) ; \
  uint8_t modi  = 0 ; \
  uint8_t i = D ; \
  do {  \
    -- i ;  \
    uint16_t const x = ( uint16_t  ) ( ( ( ( uint16_t  ) modi  ) <<  8 ) bitor  \
      ( ( uint16_t  ) ( np -> arr [ i ] ) ) ) ; \
    modi  = ( uint8_t ) ( x % div ) ; \
    np -> arr [ i ] = ( uint8_t ) ( x / div ) ; \
  } while ( i > 0 ) ; \
  return  modi ; }

# define  shifr_number_div_mod( N ) shifr_number ## N ## _div_mod

# define  shifr_number_def_set_byte(  N , D ) \
void  shifr_number ## N ## _set_byte  ( shifr_number_type ( N ) * const np0 , \
  uint8_t const x ) { \
  shifr_number_priv_type ( N ) * const np = shifr_number_pub_to_priv ( N ) ( np0 ) ; \
  memset  ( & ( np -> arr [ 1 ] ) , 0 , D - 1 ) ; \
  np -> arr [ 0 ] = x ; }

# define  shifr_number_set_byte( N ) shifr_number ## N ## _set_byte

// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 16, остаются 15! вариантов пароля
// пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
//  секретных кодов для соли+данных 0x1  
// в deshi нужна соль

// we lay out the password in the table of encryption, decryption
// password % 0x10 = 0xa means that 0xa is the encrypted code for salt + data 0x0
// divide the password by 16, 15! remain password options
// password % 0xf = 0xa is the sequence number for the remaining NOT occupied from
//  0xff secret codes for salt + data 0x1
// deshi needs salt

# define  shifr_password_load( N ) shifr_password_  ##  N ##  _load

# define  shifr_password_load_def(  N , SDS ) \
void  shifr_password_load ( N ) ( shifr_number_type ( N ) const * const password0 , \
  shifr_arrp const shifrp , shifr_arrp const deship ) { \
  shifr_initarr ( shifrp  , 0xff  , SDS ) ; \
  shifr_initarr ( deship  , 0xff  , SDS ) ; \
  uint8_t volatile  arrind  [ SDS ] ; \
  { uint8_t volatile  * arrj  = & ( arrind  [ SDS  ] ) ;  \
    uint8_t j = SDS  ;  \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ;  } \
  uint8_t inde  = 0 ; \
  shifr_number_priv_type ( N ) password = * shifr_number_const_pub_to_priv ( N ) ( \
    password0 ) ; \
  do {  \
    { uint8_t const cindex = shifr_number_div_mod ( N ) ( & password . pub ,  \
        (  uint8_t ) ( SDS - inde  ) ) ; \
      uint8_t volatile  * const arrind_cindexp = & (  arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( ( uint8_t * ) arrind_cindexp , ( uint8_t * ) arrind_cindexp + 1 , \
        ( size_t  ) ( SDS  - inde  - cindex - 1 ) ) ; } \
    ++ inde  ;  \
  } while ( inde < SDS ) ; \
  shifr_memsetv ( arrind  , shifr_memsetv_default_byte , sizeof  ( arrind  ) ) ; }

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
