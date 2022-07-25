// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_CAST_H
# define  SHIFR_CAST_H

# define  uint8_cast_uint16 shifr_uint8_cast_uint16
static  inline  uint16_t  uint8_cast_uint16 ( uint8_t const u ) {
  return  ( uint16_t  ) u ;
}

# define  uint8_cast_uint shifr_uint8_cast_uint
static  inline  unsigned int  uint8_cast_uint ( uint8_t const u ) {
  return  ( unsigned int  ) u ;
}

# define  uint16_cast_uint8 shifr_uint16_cast_uint8
static  inline  uint8_t  uint16_cast_uint8 ( uint16_t const u ) {
  return  ( uint8_t  ) u ;
}

# define  int_cast_uint8 shifr_int_cast_uint8
static  inline  uint8_t  int_cast_uint8 ( int const i ) {
  return  ( uint8_t  ) i ;
}

# define  uint_cast_uint8 shifr_uint_cast_uint8
static  inline  uint8_t  uint_cast_uint8 ( unsigned  int const u ) {
  return  ( uint8_t  ) u ;
}

# define  int_cast_uint16 shifr_int_cast_uint16
static  inline  uint16_t  int_cast_uint16 ( int const i ) {
  return  ( uint16_t  ) i ;
}

# define  uint_cast_uint16 shifr_uint_cast_uint16
static  inline  uint16_t  uint_cast_uint16 ( unsigned int const u ) {
  return  ( uint16_t  ) u ;
}

# define  int_cast_size shifr_int_cast_size
static  inline  size_t  int_cast_size ( int const i ) {
  return  ( size_t ) i ;
}

# define  int_cast_uint shifr_int_cast_uint
static  inline  unsigned  int int_cast_uint ( int const i ) {
  return  ( unsigned  int ) i ;
}

# define  char_cast_uint8 shifr_char_cast_uint8
static  inline  uint8_t  char_cast_uint8 ( char const c ) {
  return  ( uint8_t  ) c ;
}

# define  uint8_cast_char shifr_uint8_cast_char
static  inline  char  uint8_cast_char ( uint8_t const u ) {
  return  ( char ) u ;
}

# define  uint16_cast_char shifr_uint16_cast_char
static  inline  char  uint16_cast_char ( uint16_t const u ) {
  return  ( char ) u ;
}

# define  int_cast_char shifr_int_cast_char
static  inline  char  int_cast_char ( int const i ) {
  return  ( char ) i ;
}

# define  charvolatilep_cast_charp shifr_charvolatilep_cast_charp
static  inline  char * charvolatilep_cast_charp ( char volatile * const cv ) {
  return  ( char * ) cv ;
}

# define  charconstp_cast_stringconstp shifr_charconstp_cast_stringconstp
static  inline  shifr_strcp charconstp_cast_stringconstp (
  char const * const c ) {
  return  ( shifr_strcp ) c ;
}

# endif // SHIFR_CAST_H  
