// Quick implementation of TeleTrust their Admission block. Needed for
// BAK, BA-91, JP-7 and ITI medical/802.x chipcards & digital signatures
// that rely on the ISIS-MTT Specification to indication bearer their
// professional background.
//
// Common isis-mtt specifications for interoperable pki applications,
// T7 & teletrust, version 1.1 – 16 march 2004.
// <http://www.teletrust.de/fileadmin/files/ISIS-MTT_Core_Specification_v1.1.pdf>
//
//
// Copyright (c) 2012 Dirk-Willem van Gulik <dirkx@WebWeaving.org>,
//           All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may 
// not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software 
// distributed under the License is distributed on an "AS IS" BASIS, 
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and 
// limitations under the License.
//
//

#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/safestack.h>

#ifndef _X509_ADMINSSION_SYNTAX
#define _X509_ADMINSSION_SYNTAX

typedef struct NamingAuthority_st {
    ASN1_OBJECT* namingAuthorityId;
    ASN1_IA5STRING* namingAuthorityUrl;
    ASN1_STRING* namingAuthorityText;
} NAMING_AUTHORITY;
DECLARE_ASN1_ITEM(NAMING_AUTHORITY)

typedef struct ProfessionInfo_st {
    NAMING_AUTHORITY* namingAuthority;
    STACK_OF(DIRECTORYSTRING)* professionItems;
    STACK_OF(ASN1_OBJECT)* professionOIDs;
    ASN1_PRINTABLESTRING* registrationNumber;
    ASN1_OCTET_STRING* addProfessionInfo;
} PROFESSION_INFO;
DECLARE_ASN1_ITEM(PROFESSION_INFO)

typedef struct Admissions_st {
    GENERAL_NAME* admissionAuthority;
    NAMING_AUTHORITY* namingAuthority;
    STACK_OF(PROFESSION_INFO)* professionInfos;
} ADMISSIONS;
DECLARE_ASN1_ITEM(ADMISSIONS)

typedef struct AdmissionSyntax_st {
    GENERAL_NAME* admissionAuthority;
    STACK_OF(ADMISSIONS)* contentsOfAdmissions;
} ADMISSION_SYNTAX;
DECLARE_ASN1_ITEM(ADMISSION_SYNTAX)

ASN1_SEQUENCE(NAMING_AUTHORITY) = {
    ASN1_OPT(NAMING_AUTHORITY, namingAuthorityId, ASN1_OBJECT),
    ASN1_OPT(NAMING_AUTHORITY, namingAuthorityUrl, ASN1_IA5STRING),
    ASN1_OPT(NAMING_AUTHORITY, namingAuthorityText, DIRECTORYSTRING),
} ASN1_SEQUENCE_END(NAMING_AUTHORITY)

ASN1_SEQUENCE(PROFESSION_INFO) = {
    ASN1_EXP_OPT(PROFESSION_INFO, namingAuthority, NAMING_AUTHORITY, 0),
    ASN1_SEQUENCE_OF(PROFESSION_INFO, professionItems, DIRECTORYSTRING),
    ASN1_SEQUENCE_OF(PROFESSION_INFO, professionOIDs, ASN1_OBJECT),
    ASN1_OPT(PROFESSION_INFO, registrationNumber, ASN1_PRINTABLESTRING),
    ASN1_OPT(PROFESSION_INFO, addProfessionInfo, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(PROFESSION_INFO)

ASN1_SEQUENCE(ADMISSIONS) = {
    ASN1_EXP_OPT(ADMISSIONS, admissionAuthority, GENERAL_NAME, 0),
    ASN1_EXP_OPT(ADMISSIONS, namingAuthority, NAMING_AUTHORITY, 1),
    ASN1_SEQUENCE_OF(ADMISSIONS, professionInfos, PROFESSION_INFO),
} ASN1_SEQUENCE_END(ADMISSIONS)

ASN1_SEQUENCE(ADMISSION_SYNTAX) = {
    ASN1_OPT(ADMISSION_SYNTAX, admissionAuthority, GENERAL_NAME),
    ASN1_SEQUENCE_OF(ADMISSION_SYNTAX, contentsOfAdmissions, ADMISSIONS),
} ASN1_SEQUENCE_END(ADMISSION_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(NAMING_AUTHORITY);
IMPLEMENT_ASN1_FUNCTIONS(PROFESSION_INFO);
IMPLEMENT_ASN1_FUNCTIONS(ADMISSIONS);
IMPLEMENT_ASN1_FUNCTIONS(ADMISSION_SYNTAX);

int x509_add_admission_extensions();
#endif

