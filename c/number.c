// Shifr ©2020-3 Glebe A.N. numbers
// Шифр ©2020-3 Глебов А.Н. числа

# include "define.h"
# include "number/public.h"

# ifdef SHIFR_DEBUG

# define  shifr_number_def_princ( V ) \
void  shifr_number_princ  ( V ) ( shifr_number_type ( V ) const * const np , FILE * const fs ) { \
  fputs ( "[ " , fs ) ; \
  uint8_t i = shifr_number_size ( V ) - 1 ;  \
  do  { \
    fprintf ( fs  , "%02x " , shifr_number_elt_copy ( V ) ( np , i ) ) ; \
    if ( ! i ) \
      break ; \
    --  i ; \
  } while ( true ) ; \
  fputs ( "]" , fs ) ; \
}

shifr_number_def_princ  ( v2 )
shifr_number_def_princ  ( v3 )

# endif // SHIFR_DEBUG

# define  shifr_number_def_add(  N , D ) \
void  shifr_number_add  ( N ) ( shifr_number_type ( N ) * const restrict  np  , \
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

# include "cast.h"

shifr_number_def_add  ( v2 , shifr_number_size ( v2 ) )
shifr_number_def_add  ( v3 , shifr_number_size ( v3 ) )

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

# include <iso646.h> // not_eq

shifr_number_def_not_zero ( v2 , shifr_number_size ( v2 ) )
shifr_number_def_not_zero ( v3 , shifr_number_size ( v3 ) )

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

shifr_number_def_dec  ( v2 , shifr_number_size ( v2 ) )
shifr_number_def_dec  ( v3 , shifr_number_size ( v3 ) )

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

shifr_number_def_div_mod  ( v2 , shifr_number_size ( v2 ) )
shifr_number_def_div_mod  ( v3 , shifr_number_size ( v3 ) )

# define  shifr_number_def_set_byte(  N , D ) \
void  shifr_number_set_byte ( N ) ( shifr_number_type ( N ) * const np0 , \
  uint8_t const x ) { \
  shifr_number_priv_type ( N ) * const np = \
    shifr_number_pub_to_priv ( N ) ( np0 ) ; \
  memset  ( & ( np -> arr [ 1 ] ) , 0 , D - 1 ) ; \
  np -> arr [ 0 ] = x ; \
}

# include <string.h> // memset

shifr_number_def_set_byte ( v2 , shifr_number_size ( v2 ) )
shifr_number_def_set_byte ( v3 , shifr_number_size ( v3 ) )

# define  shifr_number_def_mul_byte(  N ) \
void  shifr_number_mul_byte ( N ) ( shifr_number_type ( N ) * const np  , \
  uint8_t const byte ) {  \
  if ( byte == 0 ) {  \
    shifr_number_set0 ( N ) ( np ) ; \
    return  ; \
  } \
  if ( byte == 1 )  \
    return ; \
  uint8_t per = 0 ; \
  { uint8_t i = 0 ; \
    do { \
      uint16_t const x = int_cast_uint16 ( uint8_cast_uint16 ( \
        shifr_number_elt_copy ( N ) ( np , i ) ) * \
        uint8_cast_uint16 ( byte ) + uint8_cast_uint16 ( per ) ) ; \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] =  \
        int_cast_uint8 ( x bitand 0xff ) ; \
      per = int_cast_uint8 ( x >>  8 ) ; \
      ++  i ; \
    } while ( i < shifr_number_size ( N ) ) ; \
  } \
}

shifr_number_def_mul_byte ( v2 )
shifr_number_def_mul_byte ( v3 )

# define  shifr_number_def_set0( N ) \
  void shifr_number_set0  ( N ) ( shifr_number_type  ( N ) * const np ) { \
    memset  ( & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) , 0 ,  \
      shifr_number_size ( N ) ) ; \
  }

shifr_number_def_set0 ( v2 )
shifr_number_def_set0 ( v3 )
