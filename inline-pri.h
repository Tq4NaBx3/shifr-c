// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_INLINE_PRI_H
# define  SHIFR_INLINE_PRI_H

# include <stddef.h> // offsetof
# include "template-pri.h"
# include "cast.h"

static  inline  shifr_number_pub_to_priv_def  ( v2 )
static  inline  shifr_number_pub_to_priv_def  ( v3 )
    
static  inline  shifr_number_const_pub_to_priv_def  ( v2 )
static  inline  shifr_number_const_pub_to_priv_def  ( v3 )

static  inline  uint8_t letter_to_bits6 ( char  const letter  ) {
  return  int_cast_uint8 ( char_cast_uint8 ( letter ) -
    char_cast_uint8 ( ';' ) ) ;
}

// ';' = 59 ... 'z' = 122 , 122 - 59 + 1 == 64
static  inline  char  bits6_to_letter ( uint8_t const bits6 ) {
  return  int_cast_char ( char_cast_uint8  ( ';' ) + bits6 ) ;
}
  
static inline void  data_xor3  ( uint8_t * const restrict  old_last_data ,
  uint8_t * const restrict  old_last_salt ,
  shifr_arrp  const secretdatasalt  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 3 ;
    uint8_t const cur_salt = ( * ids ) bitand 0x7 ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    // данные сыпью предыдущей солью
    // the main thing is data , the tail is salt : 101 =>
    //   101_000 or 101_001 or ... or 101_111
    // in the table, everything is side by side, 8 options are evenly
    // distributed the data is a rash of the previous salt
    ( * ids ) = int_cast_uint8 ( ( * ids ) xor
      ( ( * old_last_salt ) << 3  ) ) ;
    ( * ids ) xor_eq  ( * old_last_data ) ;
    // берю свежую соль
    // I take fresh salt
    ( * old_last_salt ) = cur_salt ;
    ( * old_last_data ) = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasalt ) [ data_size ] ) ) ;
}  
  
static inline void  shifr_crypt_decrypt ( shifr_arrp const datap ,
  shifr_arrcp const tablep , shifr_arrp const encrp , size_t const data_size )
{
  uint8_t const * id = & ( ( * datap ) [ data_size ] ) ;
  uint8_t * ied = & ( ( * encrp ) [ data_size ] ) ;
  do {
    -- id ;
    --  ied ;
    ( * ied ) = ( * tablep ) [ * id ] ;
  } while ( id not_eq & ( ( * datap ) [ 0 ] ) ) ;
}  
  
static inline void  shifr_data_xor2  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrp  const secretdatasalt  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data  = ( * ids ) >> 2 ;
    uint8_t const cur_salt  = ( * ids ) bitand  0x3 ;
    // главное данные , хвост - соль : 01 =>
    //   01_00 или 01_01 или 01_10 или 01_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // данные сыпью предыдущей солью
    // the main thing is data , the tail is salt : 01 =>
    //   01_00 or 01_01 or 01_10 or 01_11
    // in the table, everything is side by side, 4 options are evenly
    // distributed the data is a rash of the previous salt
    ( * ids ) = int_cast_uint8 ( ( * ids ) xor ( ( ns_shifrp -> old_last_salt )
        << 2  ) ) ;
    ( * ids ) xor_eq  ( ns_shifrp -> old_last_data ) ;
    // беру свежую соль
    // I take fresh salt
    ns_shifrp ->  old_last_salt = cur_salt  ;
    ns_shifrp ->  old_last_data = cur_data  ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasalt ) [ data_size ] ) ) ;
}  
  
static inline void  shifr_decrypt_salt2 ( shifr_arrp const datap ,
  shifr_arrcp const tablep , shifr_arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_salt ,
  uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_salt = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_salt >>  2 ) xor ( * old_last_salt ) ;
      ( * old_last_salt ) = int_cast_uint8 (
        (  data_salt bitand  0x3 ) xor ( * old_last_data ) ) ;
    }
    ( * old_last_data ) = ( * ide ) ;
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ;
}  
  
static inline void  shifr_decrypt_salt3 ( shifr_arrp const datap ,
  shifr_arrcp const tablep , shifr_arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_salt ,
  uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_salt = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_salt >>  3 ) xor ( * old_last_salt ) ;
      ( * old_last_salt ) = int_cast_uint8 (
        ( data_salt bitand  0x7 ) xor ( * old_last_data ) ) ;
      ( * old_last_data ) = ( * ide ) ;
    }
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ;
}  
  
static inline  void  shifr_initarr ( shifr_arrp  const p ,
  uint8_t const codefree , size_t const loc_shifr_deshi_size ) {
  uint8_t * i = & ( ( * p ) [ loc_shifr_deshi_size  ] ) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ( ( * p ) [ 0 ] ) ) ;
}
  
# endif // SHIFR_INLINE_PRI_H
