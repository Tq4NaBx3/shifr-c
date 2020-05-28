# define  strp  shifr_strp
typedef char ( * strp ) [ ] ;    

# define  strcp  shifr_strcp
typedef char const ( * strcp ) [ ] ;

# define  arrp  shifr_arrp
typedef uint8_t ( * arrp ) [ ] ;

# define  arrcp  shifr_arrcp
typedef uint8_t const ( * arrcp ) [ ] ;

# define  shifr_number_structtype( N ) \
  struct  shifr_s_number ## N ;

# define  shifr_number_type( N ) shifr_t_number ## N
# define  number_type shifr_number_type
  
# define  shifr_number_typedef( N ) \
  typedef struct  shifr_s_number ## N number_type ( N ) ;  

shifr_number_structtype( 6 )
shifr_number_typedef( 6 )
shifr_number_structtype( 37 )
shifr_number_typedef( 37 )

# define  s_raspr4  shifr_s_raspr4
struct  s_raspr4  ;
# define  t_raspr4  shifr_t_raspr4
typedef struct  s_raspr4  t_raspr4  ;

# define  s_raspr6  shifr_s_raspr6
struct  s_raspr6  ;
# define  t_raspr6  shifr_t_raspr6
typedef struct  s_raspr6  t_raspr6 ;

struct  s_ns_shifr  ;
typedef struct  s_ns_shifr  t_ns_shifr ;

# define  s_streambuf shifr_s_streambuf
struct  s_streambuf ;
# define  t_streambuf shifr_t_streambuf
typedef struct  s_streambuf t_streambuf ;
