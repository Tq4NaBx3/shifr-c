// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_CAST_H
# define  SHIFR_CAST_H

# define  uint8_cast_uint16 shifr_uint8_cast_uint16
static  inline  uint16_t  uint8_cast_uint16 ( uint8_t const u ) {
  return  ( uint16_t  ) u ;
}

# define  uint16_cast_uint8 shifr_uint16_cast_uint8
static  inline  uint8_t  uint16_cast_uint8 ( uint16_t const u ) {
  return  ( uint8_t  ) u ;
}

# define  int_cast_uint8 shifr_int_cast_uint8
static  inline  uint8_t  int_cast_uint8 ( int const i ) {
  return  ( uint8_t  ) i ;
}

# define  int_cast_uint16 shifr_int_cast_uint16
static  inline  uint16_t  int_cast_uint16 ( int const i ) {
  return  ( uint16_t  ) i ;
}

# define  int_cast_size shifr_int_cast_size
static  inline  size_t  int_cast_size ( int const i ) {
  return  ( size_t ) i ;
}

# define  char_cast_uint8 shifr_char_cast_uint8
static  inline  uint8_t  char_cast_uint8 ( char const c ) {
  return  ( uint8_t  ) c ;
}

# define  int_cast_char shifr_int_cast_char
static  inline  char  int_cast_char ( int const i ) {
  return  ( char ) i ;
}

# endif // SHIFR_CAST_H  
