// Шифр ©2020-3 Глебов А.Н. Template Private Declare
// Shifr ©2020-3 Glebe A.N.

# define  shifr_number_pub_to_priv( N ) shifr_number_pub_to_priv_ ## N

# define  shifr_number_pub_to_priv_dec( N ) \
shifr_number_priv_type ( N ) * shifr_number_pub_to_priv ( N ) ( shifr_number_type  ( N ) * )  ;

# define  shifr_number_const_pub_to_priv( N ) shifr_number_const_pub_to_priv_ ## N

# define  shifr_number_const_pub_to_priv_dec( N ) \
shifr_number_priv_type ( N ) const * shifr_number_const_pub_to_priv ( N ) ( shifr_number_type  ( N ) const * ) ;
