// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_INLINE_PRI_H
# define  SHIFR_INLINE_PRI_H

# include <stddef.h> // offsetof

# define  shifr_number_pub_to_priv( N ) shifr_number_pub_to_priv_ ## N

# define  shifr_number_pub_to_priv_def( N ) \
shifr_number_priv_type ( N ) * shifr_number_pub_to_priv ( N ) ( \
  shifr_number_type  ( N ) * const n ) { \
  return  ( shifr_number_priv_type  ( N ) * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( shifr_number_priv_type ( N ) , pub ) ) ; }
    
static  inline  shifr_number_pub_to_priv_def  ( v2 )
static  inline  shifr_number_pub_to_priv_def  ( v3 )

# define  shifr_number_const_pub_to_priv( N ) shifr_number_const_pub_to_priv_ ## N

# define  shifr_number_const_pub_to_priv_def( N ) \
shifr_number_priv_type ( N ) const * shifr_number_const_pub_to_priv ( N ) (  \
  shifr_number_type  ( N ) const * const n ) { \
  return  ( shifr_number_priv_type  ( N ) const * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( shifr_number_priv_type ( N ) , pub ) ) ; }
    
static  inline  shifr_number_const_pub_to_priv_def  ( v2 )
static  inline  shifr_number_const_pub_to_priv_def  ( v3 )

static  inline  uint8_t letter_to_bits6 ( char  const letter  ) {
  return  ( uint8_t ) ( ( ( uint8_t ) letter ) - ( ( uint8_t ) ';' ) ) ; }

// ';' = 59 ... 'z' = 122 , 122 - 59 + 1 == 64
static  inline  char  bits6_to_letter ( uint8_t const bits6 ) {
  return  ( char ) ( ( ( uint8_t ) ';' ) + bits6 ) ; }
  
static inline void  data_xor3  ( uint8_t * const restrict  old_last_data ,
  uint8_t * const restrict  old_last_sole ,
  shifr_arrp  const secretdatasole  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 3 ;
    uint8_t const cur_sole = ( * ids ) bitand 0x7 ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    // данные сыпью предыдущей солью
    ( * ids ) = ( uint8_t ) ( ( * ids ) xor  ( ( * old_last_sole ) << 3  ) ) ;
    ( * ids ) xor_eq  ( * old_last_data ) ;
    // берю свежую соль
    ( * old_last_sole ) = cur_sole ;
    ( * old_last_data ) = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasole ) [ data_size ] ) ) ; }  
  
static inline void  shifr_crypt_decrypt ( shifr_arrp const datap ,
  shifr_arrcp const tablep , shifr_arrp const encrp , size_t const data_size ) {
  uint8_t const * id = & ( ( * datap ) [ data_size ] ) ;
  uint8_t * ied = & ( ( * encrp ) [ data_size ] ) ;
  do {
    -- id ;
    --  ied ;
    ( * ied ) = ( * tablep ) [ * id ] ;
  } while ( id not_eq & ( ( * datap ) [ 0 ] ) ) ; }  
  
static inline void  shifr_data_xor2  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrp  const secretdatasole  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 2 ;
    uint8_t const cur_sole = ( * ids ) bitand 0x3 ;
    // главное данные , хвост - соль : 01 =>
    //   01_00 или 01_01 или 01_10 или 01_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // данные сыпью предыдущей солью
    ( * ids ) = ( uint8_t ) ( ( * ids ) xor ( ( ns_shifrp -> old_last_sole ) << 2  ) ) ;
    ( * ids ) xor_eq  ( ns_shifrp -> old_last_data ) ;
    // беру свежую соль
    ns_shifrp -> old_last_sole = cur_sole ;
    ns_shifrp -> old_last_data = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasole ) [ data_size ] ) ) ; }  
  
static inline void  shifr_decrypt_sole2 ( shifr_arrp const datap ,
  shifr_arrcp const tablep , shifr_arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_sole , uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_sole = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_sole >>  2 ) xor ( * old_last_sole ) ;
      ( * old_last_sole ) = ( uint8_t ) (
        (  data_sole bitand  0x3 ) xor ( * old_last_data ) ) ; }
    ( * old_last_data ) = ( * ide ) ;
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ; }  
  
static inline void  shifr_decrypt_sole3 ( shifr_arrp const datap ,
  shifr_arrcp const tablep , shifr_arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_sole , uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_sole = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_sole >>  3 ) xor ( * old_last_sole ) ;
      ( * old_last_sole ) = ( uint8_t ) (
        ( data_sole bitand  0x7 ) xor ( * old_last_data ) ) ;
      ( * old_last_data ) = ( * ide ) ; }
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ; }  
  
static inline  void  shifr_initarr ( shifr_arrp  const p , uint8_t const codefree ,
  size_t const loc_shifr_deshi_size ) {
  uint8_t * i = & ( ( * p ) [ loc_shifr_deshi_size  ] ) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ( ( * p ) [ 0 ] ) ) ; }
  
# endif // SHIFR_INLINE_PRI_H
