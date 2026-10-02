/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHREGEX_INTERNAL_H
#define SSHREGEX_INTERNAL_H

typedef enum {
  SSH_REX_BEGINNING             = 0,
  SSH_REX_END                   = 1,
  SSH_REX_LITERAL               = 2,
  SSH_REX_ANY                   = 3,
  SSH_REX_CHAR_SET              = 4,
  SSH_REX_START_SUBEXPR         = 5,
  SSH_REX_END_SUBEXPR           = 6,
  SSH_REX_ACCEPT                = 7,
  SSH_REX_DISJUNCT              = 8,
  SSH_REX_LOOKAHEAD             = 9,
  SSH_REX_LOOKBACK              = 10,

  /* These are used in the intermediary constructions. */
  SSH_REX_CONCATENATION,
  SSH_REX_PLUS,
  SSH_REX_STAR,
  SSH_REX_OPTIONAL,
  SSH_REX_RANGE,
  SSH_REX_LAZY_PLUS,
  SSH_REX_LAZY_STAR,
  SSH_REX_LAZY_OPTIONAL,
  SSH_REX_LAZY_RANGE,
  SSH_REX_SUBEXPR,
  SSH_REX_ANON_SUBEXPR,
  SSH_REX_FORWARD,
  SSH_REX_START_ANON_SUBEXPR,
  SSH_REX_END_ANON_SUBEXPR,
  SSH_REX_SUB_NFA
} SshRexMatchType;

/* Matcher proc flag definitions. */
#define SSH_REX_ACCEPT_PREFIX           0x0001

/* Flag definitions. */

/* This flag is used only when dumping NFAs to stderr, which is not
   normally done. */
#define SSH_REX_DUMPED                  0x0001

/* Used to denote those nodes that have been already examined during
   the removal of forwarding nodes. */
#define SSH_REX_STREAMLINED             0x0002

/* This flag is set for those states that can be part of accepting
   sequences even if there are no more characters available in the
   string to match against, i.e. if we are at the end.  Never set for
   consuming nodes. */
#define SSH_REX_CAN_BE_LAST             0x0008

/* Set for those nodes during compilation that really are not anchored
   due to ^. */
#define SSH_REX_NOT_ANCHORED            0x0010


/* Subexpressions are denoted by integers. */
typedef int SshRexSubexpr;

/***************************************************************** Syntaxes. */

typedef enum {
  SSH_REX_P_START_SUBEXPR,      /* Start numbered subexpression */
  SSH_REX_P_END_SUBEXPR,        /* End numbered subexpression */
  SSH_REX_P_START_ANON_SUBEXPR, /* Start anonymous subexpression */
  SSH_REX_P_END_ANON_SUBEXPR,   /* End anonymous subexpression */
  SSH_REX_P_STAR,               /* Kleene star */
  SSH_REX_P_STAR_LAZY,          /* Lazy version */
  SSH_REX_P_PLUS,               /* Once, then kleene star */
  SSH_REX_P_PLUS_LAZY,          /* Lazy version */
  SSH_REX_P_OPTIONAL,           /* Optional subexpression */
  SSH_REX_P_OPTIONAL_LAZY,      /* Lazy version */
  SSH_REX_P_START_RANGE,        /* Start construction {n,m}. */
  SSH_REX_P_END_RANGE,          /* End construction {n,m}. */
  SSH_REX_P_START_END_RANGE,    /* Both start and end range construction. */
  SSH_REX_P_END_RANGE_LAZY,     /* Lazy version */
  SSH_REX_P_DISJUNCT,           /* Disjunction */
  SSH_REX_P_LITERAL,            /* Parse as literal */
  SSH_REX_P_ANY,                /* Any char */
  SSH_REX_P_BEGINNING,          /* Anchor at beginning */
  SSH_REX_P_END,                /* Anchor at end */
  SSH_REX_P_CHARSET_START,      /* Start charset */
  SSH_REX_P_CHARSET_END,        /* End charset */
  SSH_REX_P_CHARSET_COMPLEMENT_IF_FIRST, /* If first in charset spec,
                                            complement the charset */
  SSH_REX_P_CHARSET_RANGE,      /* Range character */
  SSH_REX_P_CHARSET_POSITIVE,   /* Positive range switch */
  SSH_REX_P_CHARSET_NEGATIVE,   /* Negative range switch */
  SSH_REX_P_ESCAPE,             /* Escape character */
  SSH_REX_P_NUMERIC_LITERAL,    /* Start numeric literal */
  SSH_REX_P_HEX_LITERAL,        /* Start hexdecimal literal */
  SSH_REX_P_LOOKAHEAD,          /* Look at the next character but
                                   do not consume. The continuing regex
                                   must yield a literal or a charset. */
  SSH_REX_P_LOOKBACK,           /* Look at the previous character but
                                   do not consume. The continuing regex
                                   must yield a literal or a charset. */
  SSH_REX_P_ANY_BUT_NEWLINE,    /* Any character except for newlines.
                                   Parses as a charset. */
  SSH_REX_P_ERROR,              /* Unacceptable character */

  /* Some typically escaped literals. */
  SSH_REX_P_LITERAL_TAB,
  SSH_REX_P_LITERAL_NEWLINE,
  SSH_REX_P_LITERAL_RETURN,
  SSH_REX_P_LITERAL_LINE_FEED,
  SSH_REX_P_LITERAL_ALARM,
  SSH_REX_P_LITERAL_ESCAPE,

  /* Some predefined charsets. */
  SSH_REX_P_PDC_WORD,
  SSH_REX_P_PDC_NWORD,
  SSH_REX_P_PDC_WHITESPACE,
  SSH_REX_P_PDC_NWHITESPACE,
  SSH_REX_P_PDC_DIGIT,
  SSH_REX_P_PDC_NDIGIT,
  SSH_REX_P_PDC_NOT_NEWLINE,

  /* Some precompiled NFA fragments. */
  SSH_REX_P_PCNFA_WORD_BOUNDARY,
  SSH_REX_P_PCNFA_NWORD_BOUNDARY,
  SSH_REX_P_PCNFA_WORD_START,
  SSH_REX_P_PCNFA_WORD_END,
  SSH_REX_P_PCNFA_LINE_START,
  SSH_REX_P_PCNFA_LINE_END,

  /* These are used in fileglobbing. */
  SSH_REX_P_PCNFA_ZSH_STAR,
  SSH_REX_P_PCNFA_ZSH_STAR_STAR,
  SSH_REX_P_PCNFA_ZSH_QUESTION_MARK,

  /* Full charset. Used only in token parsing, not an assignable
     syntax class. */
  SSH_REX_P_CHARSET,

  /* Range specification. */
  SSH_REX_P_RANGE,
  SSH_REX_P_RANGE_LAZY,

  /* A pre-existing NFA fragment. Used only in parsing. */
  SSH_REX_P_NFA,

  /* End of string. */
  SSH_REX_P_EOI
} SshRexParseEntity;

typedef struct {
  char *string;
  SshRexParseEntity entity;
} SshRexCompoundEntity;

#define SSH_REX_MAX_COMPOUND_ENTITIES 10

#define SSH_REX_PARSE_FLAG_POSIX_CHARSETS 1
#define SSH_REX_PARSE_FLAG_ALWAYS_ANCHOR  2

typedef struct {
  /* Mapping of characters when not inside charset or escaped. */
  SshRexParseEntity std_map[256];

  /* Mapping of characters after escape. */
  SshRexParseEntity escape_map[256];

  /* Mapping of characters inside charsets. */
  SshRexParseEntity charset_map[256];

  SshRexCompoundEntity compounds[SSH_REX_MAX_COMPOUND_ENTITIES];

  unsigned int flags;
} SshRexParseMap;

extern const SshRexParseMap syntax_egrep;
extern const SshRexParseMap syntax_ssh;
extern const SshRexParseMap syntax_zsh;

#endif /* SSHREGEX_INTERNAL_H */

