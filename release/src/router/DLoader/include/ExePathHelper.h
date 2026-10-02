/********************************************************************
	created:	2009/08/23
	created:	23:8:2009   14:47
	filename: 	exepathhelper.h
	author:		ajie0112@gmail.com

	purpose:	To get the path & name of the current execute program.
*********************************************************************/
#ifndef __EXEPATHHELPER_H_INCLUDE__
#define __EXEPATHHELPER_H_INCLUDE__

#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32

#define  WIN32_LEAN_AND_MEAN
#include <Windows.h>

#else

#include <unistd.h>
#include <stdio.h>

#endif



/*********************************************************************
 * ClassName : ReplaceStrFunctor
 * Purpose   :
 *********************************************************************/

struct ReplaceStrFunctor
{
    void operator() (std::string& strSrc
                   , const std::string& strOlds
                   , const std::string& strNews)
    {
        size_t pos;
        pos = strSrc.find(strOlds, 0);
        while (pos != std::string::npos)
        {
            strSrc.replace(pos, strOlds.size(), strNews);
            pos = strSrc.find(strOlds, pos+strNews.size());
        }
    }
};

/*********************************************************************
 * ClassName : String split function class
 * Purpose   : split the string into segments by special delimits.
 *********************************************************************/

struct SplitStrFunctor
{
    typedef std::vector<std::string> StrVec;

    enum { DEFAULT_STRVEC_SIZE = 10 };

    void operator() (std::string& strSrc
                   , const std::string& strDelims
                   , StrVec& result)
    {
        result.reserve(DEFAULT_STRVEC_SIZE);

        size_t pos, start, end;
        start = 0;

        do
        {
            pos = strSrc.find_first_not_of(strDelims, start);

            if (pos != std::string::npos)
            {
                end = strSrc.find_first_of(strDelims, pos);

                if (end == std::string::npos)
                    end = strSrc.size();

                result.push_back(strSrc.substr(pos, end-pos));

                start = end;
            }

        } while(pos != std::string::npos);
    }
};

/*********************************************************************
 * ClassName : String joint function class
 * Purpose   : joint the input string vector to a single string.
 *********************************************************************/

struct JointStrFunctor
{
    typedef std::vector<std::string> StrVec;
    typedef StrVec::iterator         StrVecItr;

    struct AddStrFunctor
    {
        std::string& result;
        std::string  midChar;

        AddStrFunctor(std::string& init, const std::string& mid = "")
            : result(init)
            , midChar(mid)
        {
        }

        void operator() (const std::string& toAdd )
        {
            result += toAdd;
            result += midChar;
        }
    };

    void operator() (const StrVecItr& beg
                   , const StrVecItr& end
                   , std::string& strResult)
    {
        std::for_each(beg, end, AddStrFunctor(strResult, "/"));
    }
};

/*********************************************************************
 * ClassName : String filter function class
 * Purpose   : filter the special characters in the string.
 *********************************************************************/

struct FilterStrFunctor
{
    typedef std::vector<std::string> StrVec;

    struct IsBeFiltered
    {
        const StrVec& selfFilterVec;

        IsBeFiltered(const StrVec& strFilterVec) : selfFilterVec(strFilterVec)
        {
        }

        bool operator() (char input)
        {
            std::string temp("");
            temp += input;
            return (selfFilterVec.end() !=
                    std::find(selfFilterVec.begin()
                            , selfFilterVec.end()
                            , temp)
                   );
        }
    };


    void operator() (std::string& strSrc
                   , const StrVec& strFilterVec)
    {
        std::string::iterator newEnd = std::remove_if(
                    strSrc.begin()
                    , strSrc.end()
                    , IsBeFiltered(strFilterVec)
                    );
        strSrc.erase(newEnd, strSrc.end());
    }
};

/*********************************************************************
 * ClassName : GetExePath
 * Purpose   : get the path & name of the execute program.
 *********************************************************************/

struct GetExePath
{
    enum
    {
        E_MAX_PATH = 260,
    };

    std::string strExeDir;
    std::string strExeName;

    GetExePath()
    {
        char fullPath[E_MAX_PATH] = {0};

#ifdef _WIN32
        ::GetModuleFileName(NULL, fullPath, E_MAX_PATH);
#else
        char linkPath[E_MAX_PATH] = {0};
        sprintf(linkPath, "/proc/%d/exe", getpid());
        //ssize_t count = ::readlink(linkPath, fullPath, E_MAX_PATH);
        ::readlink(linkPath, fullPath, E_MAX_PATH);
#endif

        std::string strPath(fullPath);
        ReplaceStrFunctor rsf;
        rsf(strPath, "\\", "/");

        SplitStrFunctor::StrVec svRet;
        SplitStrFunctor ssf;
        ssf(strPath, "/", svRet);

        strExeName = *svRet.rbegin();
        JointStrFunctor jsf;
        jsf(svRet.begin(), svRet.end()-1, strExeDir);
    }

    const std::string& getExeDir()  const { return strExeDir;  }
    const std::string& getExeName() const { return strExeName; }

};

#endif //__EXEPATHHELPER_H_INCLUDE__
