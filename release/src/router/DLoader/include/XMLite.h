// XMLite.h: interface for the XMLite class.
//
// XMLite : XML Lite Parser Library
// by bro ( Cho,Kyung Min: bro@shinbiro.com ) 2002-10-30
// Microsoft MVP (Visual C++) bro@msmvp.com
//
// History.
// 2002-10-29 : First Coded. Parsing XMLElelement and Attributes.
//              get xml parsed string ( looks good )
// 2002-10-30 : Get Node Functions, error handling ( not completed )
// 2002-12-06 : Helper Funtion string to long
// 2002-12-12 : Entity Helper Support
// 2003-04-08 : Close,
// 2003-07-23 : add property escape_value. (now no escape on default)
// 2003-10-24 : bugfix) attribute parsing <tag a='1' \r\n/> is now ok
// 2004-03-05 : add branch copy functions
// 2004-06-14 : add _tcseistr/_tcsenistr/_tcsenicmp functions
// 2004-06-14 : now support, XML Document and PI, Comment, CDATA node
// 2004-06-15 : add GetText()/ Find() functions
// 2004-06-15 : add force_parse : now can parse HTML (not-welformed xml)
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_XMLITE_H__786258A5_8360_4AE4_BDAF_2A52F8E1B877__INCLUDED_)
#define AFX_XMLITE_H__786258A5_8360_4AE4_BDAF_2A52F8E1B877__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#pragma warning(push,3)
#include <vector>
#include <deque>
#include <string>
#include <stdlib.h>
#pragma warning(pop)
#include "typedef.h"

struct _tagXMLAttr;
typedef _tagXMLAttr XAttr, *LPXAttr;
typedef std::vector<LPXAttr> XAttrs;

struct _tagXMLNode;
typedef _tagXMLNode XNode, *LPXNode;
typedef std::vector<LPXNode> XNodes, *LPXNodes;

struct _tagXMLDocument;
typedef struct _tagXMLDocument XDoc, *LPXDoc;

// Entity Encode/Decode Support
typedef struct _tagXmlEntity
{
	TCHAR entity;					// entity ( & " ' < > )
	TCHAR ref[10];					// entity reference ( &amp; &quot; etc )
	int ref_len;					// entity reference length
}XENTITY,*LPXENTITY;

typedef struct _tagXMLEntitys : public std::vector<XENTITY>
{
	LPXENTITY GetEntity( int entity );
	LPXENTITY GetEntity( LPTSTR entity );
	int GetEntityCount( LPCTSTR str );
	int Ref2Entity( LPCTSTR estr, LPTSTR str, int strlen );
	int Entity2Ref( LPCTSTR str, LPTSTR estr, int estrlen );
	std::string Ref2Entity( LPCTSTR estr );
	std::string Entity2Ref( LPCTSTR str );

	_tagXMLEntitys(){};
	_tagXMLEntitys( LPXENTITY entities, int count );
}XENTITYS,*LPXENTITYS; //lint !e1509
extern XENTITYS entityDefault;
std::string XRef2Entity( LPCTSTR estr );
std::string XEntity2Ref( LPCTSTR str );

typedef enum
{
	PIE_PARSE_WELFORMED	= 0,
	PIE_ALONE_NOT_CLOSED,
	PIE_NOT_CLOSED,
	PIE_NOT_NESTED,
	PIE_ATTR_NO_VALUE
}PCODE;

// Parse info.
typedef struct _tagParseInfo
{
	bool		trim_value;			// [set] do trim when parse?
	bool		entity_value;		// [set] do convert from reference to entity? ( &lt; -> < )
	LPXENTITYS	entitys;			// [set] entity table for entity decode
	TCHAR		escape_value;		// [set] escape value (default '\\')
	bool		force_parse;		// [set] force parse even if xml is not welformed

	LPTSTR		xml;				// [get] xml source
	bool		erorr_occur;		// [get] is occurance of error?
	LPTSTR		error_pointer;		// [get] error position of xml source
	PCODE		error_code;			// [get] error code
	std::string error_string;		// [get] error string

	LPXDoc		doc;
	_tagParseInfo() { trim_value = false; entity_value = true; force_parse = false; entitys = &entityDefault; xml = NULL; erorr_occur = false; error_pointer = NULL; error_code = PIE_PARSE_WELFORMED; escape_value = '\\'; doc=NULL;}
}PARSEINFO,*LPPARSEINFO;
extern PARSEINFO piDefault;

// display optional environment
typedef struct _tagDispOption
{
	bool newline;			// newline when new tag
	bool reference_value;	// do convert from entity to reference ( < -> &lt; )
	char value_quotation_mark;	// val="" (default value quotation mark "
	LPXENTITYS	entitys;	// entity table for entity encode

	int tab_base;			// internal usage
	_tagDispOption() { newline = true; reference_value = true; entitys = &entityDefault; tab_base = 0; value_quotation_mark = '"'; }
}DISP_OPT, *LPDISP_OPT;
extern DISP_OPT optDefault;

// XAttr : Attribute Implementation
typedef struct _tagXMLAttr
{
	std::string name;
	std::string	value;

	_tagXMLNode*	parent;

	std::string GetXML( LPDISP_OPT opt = &optDefault );
}XAttr, *LPXAttr;

typedef enum
{
	XNODE_ELEMENT,				// general node '<element>...</element>' or <element/>
	XNODE_PI,					// <?xml version="1.0" ?>
	XNODE_COMMENT,				// <!-- comment -->
	XNODE_CDATA,				// <![CDATA[ cdata ]]>
	XNODE_DOC,					// internal virtual root
}NODE_TYPE;

// XMLNode structure
typedef struct _tagXMLNode
{
	// name and value
	std::string name;
	std::string	value;

	// internal variables
	LPXNode	parent;		// parent node
	XNodes	childs;		// child node
	XAttrs	attrs;		// attributes
	NODE_TYPE type;		// node type
	LPXDoc	doc;		// document

	// Load/Save XML
	LPTSTR	Load( LPCTSTR pszXml, LPPARSEINFO pi = &piDefault );
	std::string GetXML( LPDISP_OPT opt = &optDefault );
	std::string GetText( LPDISP_OPT opt = &optDefault );

	// internal load functions
	LPTSTR	LoadAttributes( LPCTSTR pszAttrs, LPPARSEINFO pi = &piDefault );
	LPTSTR	LoadAttributes( LPCTSTR pszAttrs, LPCTSTR pszEnd, LPPARSEINFO pi = &piDefault );
	LPTSTR	LoadProcessingInstrunction( LPCTSTR pszXml, LPPARSEINFO pi = &piDefault );
	LPTSTR	LoadComment( LPCTSTR pszXml, LPPARSEINFO pi = &piDefault );
	LPTSTR	LoadCDATA( LPCTSTR pszXml, LPPARSEINFO pi = &piDefault );

	// in own attribute list
	LPXAttr	GetAttr( LPCTSTR attrname );
	LPCTSTR	GetAttrValue( LPCTSTR attrname );
	XAttrs	GetAttrs( LPCTSTR _name );

	// in one level child nodes
	LPXNode	GetChild( LPCTSTR _name );
	LPCTSTR	GetChildValue( LPCTSTR _name );
	std::string	GetChildText( LPCTSTR _name, LPDISP_OPT opt = &optDefault );
	XNodes	GetChilds( LPCTSTR _name );
	XNodes	GetChilds();

	LPXAttr GetChildAttr( LPCTSTR _name, LPCTSTR attrname );
	LPCTSTR GetChildAttrValue( LPCTSTR _name, LPCTSTR attrname );

	// search node
	LPXNode	Find( LPCTSTR _name );

	// modify DOM
	int		GetChildCount();
	LPXNode GetChild( int i );
	XNodes::iterator GetChildIterator( LPXNode node );
	LPXNode CreateNode( LPCTSTR _name = NULL, LPCTSTR _value = NULL );
	LPXNode	AppendChild( LPCTSTR _name = NULL, LPCTSTR _value = NULL );
	LPXNode	AppendChild( LPXNode node );
	bool	RemoveChild( LPXNode node );
	LPXNode DetachChild( LPXNode node );

	// node/branch copy
	void	CopyNode( LPXNode node );
	void	CopyBranch( LPXNode branch );
	void	_CopyBranch( LPXNode node );
	LPXNode	AppendChildBranch( LPXNode node );

	// modify attribute
	LPXAttr GetAttr( int i );
	XAttrs::iterator GetAttrIterator( LPXAttr node );
	LPXAttr CreateAttr( LPCTSTR _name = NULL, LPCTSTR _value = NULL );
	LPXAttr AppendAttr( LPCTSTR _name = NULL, LPCTSTR _value = NULL );
	LPXAttr	AppendAttr( LPXAttr attr );
	bool	RemoveAttr( LPXAttr attr );
	LPXAttr DetachAttr( LPXAttr attr );

	// operator overloads
	LPXNode operator [] ( int i ) { return GetChild(i); }
	XNode& operator = ( XNode& node ) { CopyBranch(&node); return *this; }

	_tagXMLNode() { parent = NULL; doc = NULL; type = XNODE_ELEMENT; }
	virtual ~_tagXMLNode();

	void Close();
}XNode, *LPXNode;

// XMLDocument structure
typedef struct _tagXMLDocument : public XNode
{
	PARSEINFO	parse_info;

	_tagXMLDocument() { parent = NULL; doc = this; type = XNODE_DOC; }

	LPTSTR	Load( LPCTSTR pszXml, LPPARSEINFO pi = NULL );
	LPXNode	GetRoot();

}XDoc, *LPXDoc; //lint !e1509

#include <iostream>
#include <string>

void StrTrim(std::string& buffer, const std::string& trimChars)
{
    std::string::size_type first = buffer.find_first_not_of(trimChars);
    std::string::size_type last = buffer.find_last_not_of(trimChars);
    if (first == std::string::npos)
        buffer.clear();
    else if (first <= last)
        buffer = buffer.substr(first, (last+1)-first);
}

void StrTrim(std::string& buffer)
{
    std::string& trimChars = " \t\r\n";
    std::string::size_type first = buffer.find_first_not_of(trimChars);
    std::string::size_type last = buffer.find_last_not_of(trimChars);
    if (first == std::string::npos)
        buffer.clear();
    else if (first <= last)
        buffer = buffer.substr(first, (last+1)-first);
}

// Helper Funtion
inline long XStr2Int( LPCTSTR str, long default_value = 0 )
{
	return ( str && *str ) ? atol(str) : default_value;
}

inline bool XIsEmptyString( LPCTSTR str )
{
	std::string s(str);
	std::string sc(" \t\r\n");

	StrTrim(s,sc);

	return ( s.length() == 0|| s == _T("") );
}

#endif // !defined(AFX_XMLITE_H__786258A5_8360_4AE4_BDAF_2A52F8E1B877__INCLUDED_)
