// Shifr ©2020-3 Glebe A.N. number private
// Шифр ©2020-3 Глебов А.Н. число приватн

# ifndef  SHIFR_NUMBER_PRIVATE_H
# define  SHIFR_NUMBER_PRIVATE_H

# include "number/struct.h"
# include <stddef.h> // offsetof

# define  shifr_number_pub_to_priv( N ) shifr_number_pub_to_priv_ ## N

# define  shifr_number_pub_to_priv_dec( N ) \
shifr_number_priv_type ( N ) * shifr_number_pub_to_priv ( N ) ( shifr_number_type  ( N ) * )  ;

# define  shifr_number_const_pub_to_priv( N ) shifr_number_const_pub_to_priv_ ## N

# define  shifr_number_const_pub_to_priv_dec( N ) \
shifr_number_priv_type ( N ) const * shifr_number_const_pub_to_priv ( N ) ( shifr_number_type  ( N ) const * ) ;

inline  shifr_number_pub_to_priv_dec  ( v2  )
inline  shifr_number_pub_to_priv_dec  ( v3  )

inline  shifr_number_const_pub_to_priv_dec  ( v2  )
inline  shifr_number_const_pub_to_priv_dec  ( v3  )

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


# endif // SHIFR_NUMBER_PRIVATE_H
