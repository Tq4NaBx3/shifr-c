// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# define  shifr_number_pub_to_priv( N ) shifr_number_pub_to_priv_ ## N

# define  shifr_number_pub_to_priv_def( N ) \
shifr_number_priv_type ( N ) * shifr_number_pub_to_priv ( N ) ( \
  shifr_number_type  ( N ) * const n ) { \
  return  ( shifr_number_priv_type  ( N ) * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( shifr_number_priv_type ( N ) , pub ) ) ; }

# define  shifr_number_const_pub_to_priv( N ) shifr_number_const_pub_to_priv_ ## N

# define  shifr_number_const_pub_to_priv_def( N ) \
shifr_number_priv_type ( N ) const * shifr_number_const_pub_to_priv ( N ) (  \
  shifr_number_type  ( N ) const * const n ) { \
  return  ( shifr_number_priv_type  ( N ) const * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( shifr_number_priv_type ( N ) , pub ) ) ; }

# define  shifr_number_priv_def( N , D ) \
  struct  shifr_s_number_priv ## N { \
    uint8_t arr [ D ] ; \
    shifr_number_type ( N ) pub ; \
  } ;