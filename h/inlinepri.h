# include "define.h"
# ifndef  SHIFR_DEBUG

# include "cast.h"

inline  uint8_t shifr_letter_to_bits6 ( char  const letter  ) {
  return  uint_cast_uint8 ( shifr_base64_let_to_num [
    char_cast_uint8 ( letter )  - char_cast_uint8 ( '+' ) ] ) ;
}

inline  char  shifr_bits6_to_letter ( uint8_t const bits6 ) {
  return  int_cast_char ( shifr_base64_num_to_let [ bits6 ] ) ;
}
# endif

# include <iso646.h> // not_eq

inline  void  shifr_initarr ( shifr_arrvp  const p ,
  uint8_t const codefree , size_t const loc_shifr_deshi_size ) {
  uint8_t volatile  * i = & ( ( * p ) [ loc_shifr_deshi_size  ] ) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ( ( * p ) [ 0 ] ) ) ;
}
