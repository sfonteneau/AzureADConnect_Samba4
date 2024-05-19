from samba import drs_utils
from samba import net
from samba.dcerpc import drsuapi, misc
from typing import List


class AdAccountReader:
    SecurityAttributesIds = [drsuapi.DRSUAPI_ATTID_supplementalCredentials, drsuapi.DRSUAPI_ATTID_unicodePwd, drsuapi.DRSUAPI_ATTID_ntPwdHistory]
    
    def __init__(self, dc, lp, creds, samdb):
        self.lp = lp
        self.creds = creds
        self.dc: str = dc
        self._samdb = samdb
        self._drsuapi_connection = None

    @property
    def samdb(self) :
        return self._samdb
    
    @property
    def drsuapi_connection(self):
        if self._drsuapi_connection is None:
            self._drsuapi_connection = drs_utils.drsuapi_connect(self.dc, self.lp, self.creds)
        return self._drsuapi_connection
    
    def _get_account_attributes(self, account_dn, attributes_ids: List[int] = None):
        destination_dsa_guid = misc.GUID(self.samdb.get_ntds_GUID())
        source_dsa_invocation_id = misc.GUID()
        bind, handle, _ = self.drsuapi_connection

        req = drsuapi.DsGetNCChangesRequest8()
        req.destination_dsa_guid = destination_dsa_guid
        req.source_dsa_invocation_id = source_dsa_invocation_id

        naming_context = drsuapi.DsReplicaObjectIdentifier()
        naming_context.dn = account_dn

        req.naming_context = naming_context

        hwm = drsuapi.DsReplicaHighWaterMark()
        hwm.tmp_highest_usn = 0
        hwm.reserved_usn = 0
        hwm.highest_usn = 0

        req.highwatermark = hwm
        req.uptodateness_vector = None

        req.replica_flags = 0

        req.max_object_count = 1
        req.max_ndr_size = 402116
        req.extended_op = drsuapi.DRSUAPI_EXOP_REPL_SECRET

        if attributes_ids:
            partial_attribute_set = drsuapi.DsPartialAttributeSet()
            partial_attribute_set.version = 1
            partial_attribute_set.attids = attributes_ids
            partial_attribute_set.num_attids = len(attributes_ids)
            req.partial_attribute_set = partial_attribute_set
        else:
            req.partial_attribute_set = None

        req.partial_attribute_set_ex = None
        req.mapping_ctr.num_mappings = 0
        req.mapping_ctr.mappings = None

        _, ctr = bind.DsGetNCChanges(handle, 8, req)

        identifier = ctr.first_object.object.identifier
        attributes = ctr.first_object.object.attribute_ctr.attributes

        return bind, identifier, attributes
    
    def get_account_attributes(self, account_dn, decrypted: bool = True,  attributes_ids: List[int] = SecurityAttributesIds) -> List[drsuapi.DsReplicaAttribute]:
        bind, identifier, attributes = self._get_account_attributes(str(account_dn), attributes_ids)

        if decrypted:
            rid = identifier.sid.split()[1]
            net_ctx = net.Net(self.creds)
            for attr in attributes:
                net_ctx.replicate_decrypt(bind, attr, rid)
        return attributes
    
    @staticmethod
    def get_attribute_blob(attributes, attribute_id: int) -> bytes:
        for attr in attributes:
            if attr.attid == attribute_id:
                if attr.value_ctr.num_values != 1:
                    return None
                return attr.value_ctr.values[0].blob
        return None
    
    @staticmethod
    def get_unicodePwd(attributes):
        return AdAccountReader.get_attribute_blob(attributes, drsuapi.DRSUAPI_ATTID_unicodePwd)
