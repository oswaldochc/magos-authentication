<?php

namespace Magos\Authentication\Adapter;

use Zend\Authentication\Adapter\DbTable;
use Zend\Authentication\Adapter\DbTable\Exception\RuntimeException as ExceptionRuntimeException;
use Zend\Authentication\Result as AuthenticationResult;
use Zend\Db\Sql;
use Zend\Crypt\Password\Bcrypt;
use Zend\Db\Sql\Predicate\Operator as SqlOp;

/**
 * Class BcryptDbAdapter
 */
class BcryptDbAdapter extends DbTable\AbstractAdapter
{
    /**
     * Función Modificada
     *
     * @return \Zend\Db\Sql\Select
     */
    protected function authenticateCreateSelect()
    {
        $dbSelect = clone $this->getDbSelect();
        $dbSelect->from($this->tableName)
            ->columns(array('*'))
            ->where(new SqlOp($this->identityColumn, '=', $this->identity));

        return $dbSelect;
    }
    /**
     * _authenticateValidateResult() - This method attempts to validate that
     * the record in the resultset is indeed a record that matched the
     * identity provided to this adapter.
     * Función Obtenida de CredentialTreatmentAdapter
     * @param  array $resultIdentity
     * @return AuthenticationResult
     */
    protected function authenticateValidateResult($resultIdentity)
    {
        if ($resultIdentity['zend_auth_credential_match'] != '1') {
            $this->authenticateResultInfo['code']       = AuthenticationResult::FAILURE_CREDENTIAL_INVALID;
            $this->authenticateResultInfo['messages'][] = 'Supplied credential is invalid.';
            return $this->authenticateCreateAuthResult();
        }

        unset($resultIdentity['zend_auth_credential_match']);
        $this->resultRow = $resultIdentity;

        $this->authenticateResultInfo['code']       = AuthenticationResult::SUCCESS;
        $this->authenticateResultInfo['messages'][] = 'Authentication successful.';
        return $this->authenticateCreateAuthResult();
    }

    /*Función Modificada se aumentó Bcrypt*/
    protected function authenticateQuerySelect(Sql\Select $dbSelect)
    {
        $sql = new Sql\Sql($this->zendDb);
        $statement = $sql->prepareStatementForSqlObject($dbSelect);
        // echo $dbSelect->getSqlString();exit;

        try {
            $result = $statement->execute();
            $resultIdentities = array();

            // create object ob Bcrypt class
            $bcrypt = new Bcrypt();

            // iterate result, most cross platform way
            foreach ($result as $row) {
                if (isset($row['ZEND_AUTH_CREDENTIAL_MATCH'])) {
                    $row['zend_auth_credential_match'] = $row['ZEND_AUTH_CREDENTIAL_MATCH'];
                    unset($row['ZEND_AUTH_CREDENTIAL_MATCH']);
                }
                if ($bcrypt->verify($this->credential, $row[$this->credentialColumn])) {
                    $row['zend_auth_credential_match'] = 1;
                    $resultIdentities[] = $row;
                }
            }

        } catch (\Exception $e) {
            throw new ExceptionRuntimeException(
                'The supplied parameters to DbTable failed to '
                . 'produce a valid sql statement, please check table and column names '
                . 'for validity.', 0, $e
            );
        }

        return $resultIdentities;
    }
}