// Shifr ©2020-3 Glebe A.N. number type
// Шифр ©2020-3 Глебов А.Н. тип чисел

# define  shifr_number_struct_name( N ) shifr_s_number_ ## N

# define  shifr_number_structtype( N ) struct  shifr_number_struct_name ( N ) ;
  
# define  shifr_number_type( N ) shifr_t_number_ ## N

# define  shifr_number_typedef( N ) \
  typedef struct  shifr_number_struct_name ( N ) shifr_number_type ( N ) ;

# define  shifr_number_priv_structname( N ) shifr_s_number_priv_ ## N

# define  shifr_number_priv_structtype( N ) struct  shifr_number_priv_structname ( N ) ;

# define  shifr_number_priv_type( N ) shifr_t_number_priv_ ## N

# define  shifr_number_priv_typedef( N ) \
  typedef struct  shifr_number_priv_structname ( N ) shifr_number_priv_type ( N ) ;

shifr_number_structtype ( v2 )
shifr_number_typedef  ( v2 )
shifr_number_structtype ( v3 )
shifr_number_typedef  ( v3 )

shifr_number_priv_structtype  ( v2 )
shifr_number_priv_typedef ( v2 )
shifr_number_priv_structtype  ( v3 )
shifr_number_priv_typedef ( v3 )

# include "number/enum.h"

typedef enum  shifr_e_number_size shifr_t_number_size ;
