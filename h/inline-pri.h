// Шифр ©2020-3 Глебов А.Н.
// Shifr ©2020-3 Glebe A.N.

# ifndef  SHIFR_INLINE_PRI_H
# define  SHIFR_INLINE_PRI_H

# include <stddef.h> // offsetof

# define  shifr_number_pub_to_priv_def( N ) \
shifr_number_priv_type ( N ) * shifr_number_pub_to_priv ( N ) ( \
  shifr_number_type  ( N ) * const n ) { \
  return  ( shifr_number_priv_type  ( N ) * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( shifr_number_priv_type ( N ) , pub ) ) ; \
}

# define  shifr_number_const_pub_to_priv_def( N ) \
shifr_number_priv_type ( N ) const * shifr_number_const_pub_to_priv ( N ) (  \
  shifr_number_type  ( N ) const * const n ) { \
  return  ( shifr_number_priv_type  ( N ) const * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( shifr_number_priv_type ( N ) , pub ) ) ; \
}

inline  shifr_number_pub_to_priv_def  ( v2 )
inline  shifr_number_pub_to_priv_def  ( v3 )
    
inline  shifr_number_const_pub_to_priv_def  ( v2 )
inline  shifr_number_const_pub_to_priv_def  ( v3 )

inline  uint8_t shifr_letter_to_bits6 ( char  const letter  ) {
  return  int_cast_uint8 ( char_cast_uint8 ( letter ) -
    char_cast_uint8 ( ';' ) ) ;
}

// ';' = 59 ... 'z' = 122 , 122 - 59 + 1 == 64
inline  char  shifr_bits6_to_letter ( uint8_t const bits6 ) {
  return  int_cast_char ( char_cast_uint8  ( ';' ) + bits6 ) ;
}

# include <iso646.h> // not_eq

inline  void  shifr_initarr ( shifr_arrvp  const p ,
  uint8_t const codefree , size_t const loc_shifr_deshi_size ) {
  uint8_t volatile  * i = & ( ( * p ) [ loc_shifr_deshi_size  ] ) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ( ( * p ) [ 0 ] ) ) ;
}

# endif // SHIFR_INLINE_PRI_H
