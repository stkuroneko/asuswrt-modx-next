/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Data Plane - Public API for Quicksec Data Plane
*/

#ifndef DATA_PLANE_H
#define DATA_PLANE_H

#include "public_defs.h"

#include "ipsec_control.h"

/**
   Data Plane configuration parameters.
 */
typedef struct DataPlaneParamsRec
{
    int dummy_param;

} DataPlaneParamsStruct, *DataPlaneParams;

/**
   Data Plane handle.
 */
typedef struct DataPlaneRec *DataPlane;


/**
   Function initializes Data Plane functionality.

   @param params
   The Data Plane parameters

   @return
   Returns Data Plane handle if initialization is successful and
   otherwise NULL.
*/
DataPlane
data_plane_init(
        DataPlaneParams params);

/**
   Function uninitializes Data Plane functionality.

   @param data_plane
   The Data Plane handle
*/
void
data_plane_uninit(
        DataPlane data_plane);

bool
data_plane_set_ipsec_control_handle(
        DataPlane data_plane,
        struct IPsecControl *ipsec_control);

void
data_plane_remove_ipsec_control_handle(
        DataPlane data_plane);

#endif /* DATA_PLANE_H */
