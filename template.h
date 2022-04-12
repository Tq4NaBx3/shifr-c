// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# include "define.h"

# define  shifr_number_def_set0( N , D ) \
  void shifr_number ## N ## _set0  ( shifr_number_type  ( N ) * const np ) { \
    memset  ( & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) , 0 , D ) ; }

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
void  shifr_string_to_password  ##  N ##  _templ ( t_ns_shifr * const ns_shifrp , \
  shifr_strvcp  const string  , shifr_number_type ( N ) * const password ,  \
  shifr_strcp const letters , uint8_t const letterscount  ) { \
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
