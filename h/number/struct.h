// Shifr ©2020-3 Glebe A.N. number structs
// Шифр ©2020-3 Глебов А.Н. структуры числа

# ifndef  SHIFR_NUMBER_STRUCT_H
# define  SHIFR_NUMBER_STRUCT_H

# include <stdint.h>
# include "number/type.h"

# define  shifr_number_def( N ) \
  struct  shifr_number_struct_name ( N ) { \
    uint8_t _ ; \
  } ;
  
shifr_number_def  ( v2 )  
shifr_number_def  ( v3 )

# define  shifr_number_priv_def( N , D ) \
  struct  shifr_number_priv_structname ( N ) { \
    uint8_t arr [ D ] ; \
    shifr_number_type ( N ) pub ; \
  } ;

shifr_number_priv_def ( v2 , shifr_number_size ( v2 ) )
shifr_number_priv_def ( v3 , shifr_number_size ( v3 ) )

# endif // SHIFR_NUMBER_STRUCT_H
