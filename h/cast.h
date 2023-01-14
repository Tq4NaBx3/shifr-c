// Shifr ©2020-3 Glebe A.N. type conversion
// Шифр ©2020-3 Глебов А.Н. приведение типа

# ifndef  SHIFR_CAST_H
# define  SHIFR_CAST_H

# include <stdint.h> // uint16_t

# define  uint8_cast_uint16 shifr_uint8_cast_uint16
inline  uint16_t  uint8_cast_uint16 ( uint8_t ) ;

# define  uint8_cast_uint shifr_uint8_cast_uint
inline  unsigned int  uint8_cast_uint ( uint8_t ) ;

# define  uint16_cast_uint8 shifr_uint16_cast_uint8
inline  uint8_t  uint16_cast_uint8 ( uint16_t ) ;

# define  int_cast_uint8 shifr_int_cast_uint8
inline  uint8_t  int_cast_uint8 ( int ) ;

# define  uint_cast_uint8 shifr_uint_cast_uint8
inline  uint8_t  uint_cast_uint8 ( unsigned  int ) ;

# define  int_cast_uint16 shifr_int_cast_uint16
inline  uint16_t  int_cast_uint16 ( int ) ;

# define  uint_cast_uint16 shifr_uint_cast_uint16
inline  uint16_t  uint_cast_uint16 ( unsigned int ) ;

# define  int_cast_size shifr_int_cast_size
inline  size_t  int_cast_size ( int ) ;

# define  int_cast_uint shifr_int_cast_uint
inline  unsigned  int int_cast_uint ( int ) ;

# define  char_cast_uint8 shifr_char_cast_uint8
inline  uint8_t  char_cast_uint8 ( char ) ;

# define  uint8_cast_char shifr_uint8_cast_char
inline  char  uint8_cast_char ( uint8_t ) ;

# define  uint16_cast_char shifr_uint16_cast_char
inline  char  uint16_cast_char ( uint16_t ) ;

# define  int_cast_char shifr_int_cast_char
inline  char  int_cast_char ( int ) ;

# define  charvolatilep_cast_charp shifr_charvolatilep_cast_charp
inline  char * charvolatilep_cast_charp ( char volatile * ) ;

# define  uint8volatilep_cast_unt8p shifr_uint8volatilep_cast_unt8p
inline  uint8_t * uint8volatilep_cast_unt8p ( uint8_t volatile * ) ;

# define  charconstp_cast_stringconstp shifr_charconstp_cast_stringconstp
inline  shifr_strcp charconstp_cast_stringconstp ( char const * ) ;

# define  lint_cast_ulint shifr_lint_cast_ulint
inline  unsigned  long  int lint_cast_ulint ( long  int ) ;

# define  ulint_cast_uint shifr_ulint_cast_uint
inline  unsigned int ulint_cast_uint ( unsigned long  int ) ;

# define  ulint_cast_lint shifr_ulint_cast_lint
inline  long int ulint_cast_lint ( unsigned long  int ) ;

# define  uint8_cast_uint16 shifr_uint8_cast_uint16
inline  uint16_t  uint8_cast_uint16 ( uint8_t const u ) {
  return  ( uint16_t  ) u ;
}

# define  uint8_cast_uint shifr_uint8_cast_uint
inline  unsigned int  uint8_cast_uint ( uint8_t const u ) {
  return  ( unsigned int  ) u ;
}

# define  uint16_cast_uint8 shifr_uint16_cast_uint8
inline  uint8_t  uint16_cast_uint8 ( uint16_t const u ) {
  return  ( uint8_t  ) u ;
}

# define  int_cast_uint8 shifr_int_cast_uint8
inline  uint8_t  int_cast_uint8 ( int const i ) {
  return  ( uint8_t  ) i ;
}

# define  uint_cast_uint8 shifr_uint_cast_uint8
inline  uint8_t  uint_cast_uint8 ( unsigned  int const u ) {
  return  ( uint8_t  ) u ;
}

# define  int_cast_uint16 shifr_int_cast_uint16
inline  uint16_t  int_cast_uint16 ( int const i ) {
  return  ( uint16_t  ) i ;
}

# define  uint_cast_uint16 shifr_uint_cast_uint16
inline  uint16_t  uint_cast_uint16 ( unsigned int const u ) {
  return  ( uint16_t  ) u ;
}

# define  int_cast_size shifr_int_cast_size
inline  size_t  int_cast_size ( int const i ) {
  return  ( size_t ) i ;
}

# define  int_cast_uint shifr_int_cast_uint
inline  unsigned  int int_cast_uint ( int const i ) {
  return  ( unsigned  int ) i ;
}

# define  char_cast_uint8 shifr_char_cast_uint8
inline  uint8_t  char_cast_uint8 ( char const c ) {
  return  ( uint8_t  ) c ;
}

# define  uint8_cast_char shifr_uint8_cast_char
inline  char  uint8_cast_char ( uint8_t const u ) {
  return  ( char ) u ;
}

# define  uint16_cast_char shifr_uint16_cast_char
inline  char  uint16_cast_char ( uint16_t const u ) {
  return  ( char ) u ;
}

# define  int_cast_char shifr_int_cast_char
inline  char  int_cast_char ( int const i ) {
  return  ( char ) i ;
}

# define  charvolatilep_cast_charp shifr_charvolatilep_cast_charp
inline  char * charvolatilep_cast_charp ( char volatile * const cv ) {
  return  ( char * ) cv ;
}

# define  uint8volatilep_cast_unt8p shifr_uint8volatilep_cast_unt8p
inline  uint8_t * uint8volatilep_cast_unt8p ( uint8_t volatile * const bv ) {
  return  ( uint8_t * ) bv ;
}

# define  charconstp_cast_stringconstp shifr_charconstp_cast_stringconstp
inline  shifr_strcp charconstp_cast_stringconstp ( char const * const c ) {
  return  ( shifr_strcp ) c ;
}

# define  lint_cast_ulint shifr_lint_cast_ulint
inline  unsigned  long  int lint_cast_ulint ( long  int const li  ) {
  return  ( unsigned  long  int ) li ;
}

# define  ulint_cast_uint shifr_ulint_cast_uint
inline  unsigned int ulint_cast_uint ( unsigned long  int const uli  ) {
  return  ( unsigned  int ) uli ;
}

# define  ulint_cast_lint shifr_ulint_cast_lint
inline  long int ulint_cast_lint ( unsigned long  int const uli  ) {
  return  ( long  int ) uli ;
}

# endif // SHIFR_CAST_H  
