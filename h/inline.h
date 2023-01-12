// Шифр ©2020-3 Глебов А.Н.
// Shifr ©2020-3 Glebe A.N.

# ifndef  SHIFR_INLINE_H
# define  SHIFR_INLINE_H

# define  shifr_number_def_elt_copy( N ) \
uint8_t shifr_number_elt_copy ( N ) ( \
  shifr_number_type ( N ) const * const np  , uint8_t const i ) { \
  return  shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ i ] ; \
}

# include "private.h"
# include "struct.h"
# include "public.h"

inline  shifr_number_def_elt_copy ( v2 )
inline  shifr_number_def_elt_copy ( v3 )

# include "inline-pri.h"
# include "cast.h"

# endif //  SHIFR_INLINE_H
