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

#include "x509v3-admissionsyntax.h"

static int i2r_NAMING_AUTHORITY(const struct v3_ext_method *method, void *in, BIO *bp, int ind) {
    NAMING_AUTHORITY * namingAuthority = (NAMING_AUTHORITY*)in;
    
    if (!namingAuthority || !namingAuthority->namingAuthorityId || !namingAuthority->namingAuthorityText || !namingAuthority->namingAuthorityUrl)
        return 0;
    
    if (BIO_printf(bp, "%*snamingAuthority: ", ind, "") <= 0) goto err;
    
    if (namingAuthority->namingAuthorityId ) {
        char objbuf[128];
        const char *ln = OBJ_nid2ln(OBJ_obj2nid(namingAuthority->namingAuthorityId));
        
        if (BIO_printf(bp, "%*s  admissionAuthorityId: ", ind, "") <= 0) goto err;
        OBJ_obj2txt(objbuf, sizeof objbuf, namingAuthority->namingAuthorityId, 1);
        
        if (BIO_printf(bp, "%s%s%s%s\n", ln ? ln : "", ln ? " (":"", objbuf, ln ? ")" : "") <= 0) goto err;
    };
    if (namingAuthority->namingAuthorityText) {
        if (BIO_printf(bp, "%*s  namingAuthorityText: ", ind, "") <= 0) goto err;
        if (ASN1_STRING_print(bp, namingAuthority->namingAuthorityText) <= 0) goto err;
        if (BIO_printf(bp, "\n") <= 0) goto err;
    }
    if (namingAuthority->namingAuthorityUrl) {
        if (BIO_printf(bp, "%*s  namingAuthorityUrl: ", ind, "") <= 0) goto err;
        if (ASN1_STRING_print(bp, namingAuthority->namingAuthorityUrl) <= 0) goto err;
        if (BIO_printf(bp, "\n") <= 0) goto err;
    }
    
    return 1;
err:
    return 0;
}
static int i2r_ADMISSION_SYNTAX(const struct v3_ext_method *method, void *in, BIO *bp, int ind) {
    ADMISSION_SYNTAX * admission = (ADMISSION_SYNTAX *)in;
    
    if (admission->admissionAuthority) {
        if (BIO_printf(bp, "%*sadmissionAuthority:\n", ind, "") <= 0) goto err;
        if (BIO_printf(bp, "%*s  ", ind, "") <= 0) goto err;
        if (GENERAL_NAME_print(bp, admission->admissionAuthority) <= 0) goto err;
        if (BIO_printf(bp, "\n") <= 0) goto err;
    }
    
    for(int i = 0; i < sk_num((const struct stack_st *)admission->contentsOfAdmissions); i++) {
        ADMISSIONS * entry = sk_value((const struct stack_st *)admission->contentsOfAdmissions, i);
        
        if (BIO_printf(bp, "%*sEntry %0d:\n", ind, "", 1 + i) <= 0) goto err;
        
        if (entry->admissionAuthority) {
            if (BIO_printf(bp, "%*s  admissionAuthority:\n", ind, "") <= 0) goto err;
            if (BIO_printf(bp, "%*s    ", ind, "") <= 0) goto err;
            if (GENERAL_NAME_print(bp, entry->admissionAuthority) <= 0) goto err;
            if (BIO_printf(bp, "\n") <= 0) goto err;
        }
        
        if (entry->namingAuthority) {
            if (i2r_NAMING_AUTHORITY(method, entry->namingAuthority, bp, ind) <= 0) goto err;
        }
        
        for(int j = 0; j < sk_num((const struct stack_st *)entry->professionInfos); j++) {
            PROFESSION_INFO * pinfo = sk_value((const struct stack_st *)entry->professionInfos, j);
            
            if (BIO_printf(bp, "%*s  Profession Info Entry %0d:\n", ind, "", 1 + j) <= 0) goto err;
            
            if (pinfo->registrationNumber) {
                if (BIO_printf(bp, "%*s    registrationNumber: ", ind, "") <= 0) goto err;
                if (ASN1_STRING_print(bp, pinfo->registrationNumber) <= 0) goto err;
                if (BIO_printf(bp, "\n") <= 0) goto err;
            }
            
            if (pinfo->namingAuthority) {
                if (i2r_NAMING_AUTHORITY(method, entry->namingAuthority, bp, ind+2) <= 0) goto err;
            }
            
            if (pinfo->professionItems) {
                if (BIO_printf(bp, "%*s    Info Entries:\n", ind, "") <= 0) goto err;
                for(int k = 0; k < sk_num((const struct stack_st *)pinfo->professionItems); k++) {
                    if (BIO_printf(bp, "%*s      ", ind, "") <= 0) goto err;

                    ASN1_STRING * val = sk_value((const struct stack_st *)pinfo->professionItems, k);
                    if (ASN1_STRING_print(bp, val) <= 0) goto err;
                    if (BIO_printf(bp, "\n") <= 0) goto err;
                }
            }
            
            if (pinfo->professionOIDs) {
                if (BIO_printf(bp, "%*s    Profession OIDs:\n", ind, "") <= 0) goto err;
                for(int k = 0; k < sk_num((const struct stack_st *)pinfo->professionOIDs); k++) {
                    ASN1_OBJECT * o = sk_value((const struct stack_st *)pinfo->professionOIDs, k);
                    const char *ln = OBJ_nid2ln(OBJ_obj2nid(o));
                    char objbuf[128];
                    
                    // if (BIO_printf(bp, "%*s      Entry %0d:\n", ind, "", 1 + k) <= 0) goto err;
                    OBJ_obj2txt(objbuf, sizeof objbuf, o, 1);
                    if (BIO_printf(bp, "%*s      %s%s%s%s\n", ind, "", ln ? ln : "", ln ? " (":"", objbuf, ln ? ")" : "") <= 0) goto err;
                }
            }
        }
    }
    
    return 1;
err:
    return -1;
}

static X509V3_EXT_METHOD ext_admission = {
    .ext_nid = 0,
    .ext_flags = 0,
    .it = ASN1_ITEM_ref(ADMISSION_SYNTAX),
    .i2s = NULL,
    .s2i = NULL,
    .i2v = NULL,
    .v2i = NULL,
    .r2i = NULL,
    .i2r = &i2r_ADMISSION_SYNTAX,
};


int x509_add_admission_extensions()

{
    ext_admission.ext_nid = OBJ_create("1.3.36.8.3.3", "Admission", "Professional Information or basis for Admission");
    X509V3_EXT_add(&ext_admission);
    
    return ext_admission.ext_nid;
}

