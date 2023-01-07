// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_TYPE_H
# define  SHIFR_TYPE_H

# include <stdint.h>
# include "define.h"

typedef char ( * shifr_strp ) [ ] ;
typedef char  volatile  ( * shifr_strvp ) [ ] ;
typedef char const ( * shifr_strcp  ) [ ] ;
typedef char  volatile  const ( * shifr_strvcp  ) [ ] ;
typedef uint8_t ( * shifr_arrp  ) [ ] ;
typedef uint8_t const ( * shifr_arrcp ) [ ] ;
struct  shifr_s_arrcps  ;
typedef struct  shifr_s_arrcps  shifr_arrcps  ;
struct  shifr_s_arrps ;
typedef struct  shifr_s_arrps shifr_arrps ;
struct  shifr_s_size_io ;
typedef struct  shifr_s_size_io shifr_size_io ;

# define  shifr_number_structtype( N ) \
  struct  shifr_s_number ## N ;
  
# define  shifr_number_type( N ) shifr_t_number ## N

# define  shifr_number_typedef( N ) \
  typedef struct  shifr_s_number ## N shifr_number_type ( N ) ;    
  
# define  shifr_number_priv_structtype( N ) \
  struct  shifr_s_number_priv ## N ;

# define  shifr_number_priv_type( N ) shifr_t_number_priv ## N

# define  shifr_number_priv_typedef( N ) \
  typedef struct  shifr_s_number_priv ## N shifr_number_priv_type ( N ) ;  

// log(2,16!) ceil 8 = 6
// log(2,64!) ceil 8 = 37
enum  shifr_e_number_size { shifr_number_size2  = 6 ,
  shifr_number_size3  = 37  
} ;
typedef enum  shifr_e_number_size shifr_t_number_size ;

shifr_number_structtype( v2 )
shifr_number_typedef( v2 )
shifr_number_structtype( v3 )
shifr_number_typedef( v3 )

shifr_number_priv_structtype( v2 )
shifr_number_priv_typedef( v2 )
shifr_number_priv_structtype( v3 )
shifr_number_priv_typedef( v3 )

struct  shifr_s_raspr2  ;
typedef struct  shifr_s_raspr2  shifr_t_raspr2  ;

struct  shifr_s_raspr3  ;
typedef struct  shifr_s_raspr3  shifr_t_raspr3  ;

struct  s_ns_shifr  ;
typedef struct  s_ns_shifr  t_ns_shifr ;

struct  shifr_s_streambuf ;
typedef struct  shifr_s_streambuf shifr_t_streambuf ;

// 4 * 4 = 16 = 0x10

// 8 * 8 = 64 = 0x40

enum  shifr_e_deshi_size  {
  shifr_deshi_size2 = 0x10 ,
  shifr_deshi_size3 = 0x40
} ;
typedef enum  shifr_e_deshi_size  shifr_t_deshi_size  ;

# ifdef SHIFR_DEBUG

typedef long  long  int shifr_timestamp_t ;

# endif // SHIFR_DEBUG
# endif //  SHIFR_TYPE_H