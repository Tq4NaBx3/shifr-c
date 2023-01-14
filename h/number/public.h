// Shifr ©2020-3 Glebe A.N. public functions of numbers
// Шифр ©2020-3 Глебов А.Н. публичные функции чисел

# ifndef  SHIFR_NUMBER_PUBLIC_H
# define  SHIFR_NUMBER_PUBLIC_H

# include "define.h"
# include "number/type.h"
  
# ifdef SHIFR_DEBUG

# define  shifr_number_princ( N ) shifr_number_  ##  N ##  _princ

# define  shifr_number_dec_princ( N ) \
void  shifr_number_princ  ( N ) ( shifr_number_type ( N ) const * np , FILE * fs ) ;

# include <stdio.h>

shifr_number_dec_princ  ( v2 )
shifr_number_dec_princ  ( v3 )

# endif // SHIFR_DEBUG

# define  shifr_number_elt_copy( N ) shifr_number_ ## N ## _elt_copy

# define  shifr_number_dec_elt_copy(  N ) \
uint8_t shifr_number_elt_copy ( N ) ( shifr_number_type ( N ) const * np  , uint8_t i ) ;

# include <stdint.h>

inline  shifr_number_dec_elt_copy ( v2  )
inline  shifr_number_dec_elt_copy ( v3  )

# define  shifr_number_def_elt_copy( N ) \
uint8_t shifr_number_elt_copy ( N ) ( \
  shifr_number_type ( N ) const * const np  , uint8_t const i ) { \
  return  shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ i ] ; \
}

# include "number/private.h"

inline  shifr_number_def_elt_copy ( v2 )
inline  shifr_number_def_elt_copy ( v3 )

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

# define  shifr_number_mul_byte( N ) shifr_number_ ## N ## _mul_byte

# define  shifr_number_dec_mul_byte(  N ) \
void  shifr_number_mul_byte ( N ) ( shifr_number_type ( N ) * , uint8_t )  ;

shifr_number_dec_mul_byte ( v2 )
shifr_number_dec_mul_byte ( v3 )

# define  shifr_number_set0( N ) shifr_number_ ## N ## _set0

# define  shifr_number_dec_set0( N ) \
  void shifr_number_set0  ( N )  ( shifr_number_type  ( N ) * ) ;

shifr_number_dec_set0 ( v2 )
shifr_number_dec_set0 ( v3 )

# endif // SHIFR_NUMBER_PUBLIC_H
