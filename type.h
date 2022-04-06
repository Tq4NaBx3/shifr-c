# ifndef  SHIFR_TYPE_H
# define  SHIFR_TYPE_H

# include <stdint.h>

typedef char ( * shifr_strp ) [ ] ;
typedef shifr_strp  strp  ;

typedef char  volatile  ( * shifr_strvp ) [ ] ;
typedef shifr_strvp strvp ;

typedef char const ( * shifr_strcp  ) [ ] ;
typedef shifr_strcp strcp ;

typedef char  volatile  const ( * shifr_strvcp  ) [ ] ;
typedef shifr_strvcp  strvcp  ;

typedef uint8_t ( * shifr_arrp  ) [ ] ;
typedef shifr_arrp  arrp  ;

typedef uint8_t const ( * shifr_arrcp ) [ ] ;
typedef shifr_arrcp arrcp ;

struct  shifr_s_arrcps  ;
typedef struct  shifr_s_arrcps  arrcps  ;

struct  shifr_s_arrps ;
typedef struct  shifr_s_arrps arrps ;

struct  shifr_s_size_io ;
typedef struct  shifr_s_size_io size_io ;

# define  shifr_number_structtype( N ) \
  struct  shifr_s_number ## N ;
  
# define  shifr_number_type( N ) shifr_t_number ## N
# define  number_type shifr_number_type

# define  shifr_number_typedef( N ) \
  typedef struct  shifr_s_number ## N number_type ( N ) ;    
  
# define  shifr_number_priv_structtype( N ) \
  struct  shifr_s_number_priv ## N ;

# define  shifr_number_priv_type( N ) shifr_t_number_priv ## N
# define  number_priv_type shifr_number_priv_type

# define  shifr_number_priv_typedef( N ) \
  typedef struct  shifr_s_number_priv ## N number_priv_type ( N ) ;  

// log(2,16!) ceil 8 = 6
// log(2,64!) ceil 8 = 37
enum  shifr_e_number_size { number_size2  = 6 , number_size3  = 37  } ;
typedef enum  shifr_e_number_size e_number_size ;

shifr_number_structtype( number_size2 )
shifr_number_typedef( number_size2 )
shifr_number_structtype( number_size3 )
shifr_number_typedef( number_size3 )

shifr_number_priv_structtype( number_size2 )
shifr_number_priv_typedef( number_size2 )
shifr_number_priv_structtype( number_size3 )
shifr_number_priv_typedef( number_size3 )

struct  shifr_s_raspr2  ;
typedef struct  shifr_s_raspr2  shifr_t_raspr2  ;
typedef shifr_t_raspr2  t_raspr2  ;

struct  shifr_s_raspr3  ;
typedef struct  shifr_s_raspr3  shifr_t_raspr3  ;
typedef shifr_t_raspr3  t_raspr3  ;

struct  s_ns_shifr  ;
typedef struct  s_ns_shifr  t_ns_shifr ;

struct  shifr_s_streambuf ;
typedef struct  shifr_s_streambuf shifr_t_streambuf ;
typedef shifr_t_streambuf t_streambuf ;

// 4 * 4 = 16 = 0x10

// 8 * 8 = 64 = 0x40

enum  shifr_e_deshi_size  { shifr_deshi_size2 = 0x10  , deshi_size2 = 0x10  ,
  shifr_deshi_size3 = 0x40  , deshi_size3 = 0x40  } ;
typedef enum  shifr_e_deshi_size  shifr_t_deshi_size  ;
typedef shifr_t_deshi_size  t_deshi_size  ;

# endif //  SHIFR_TYPE_H
