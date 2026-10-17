<?php
namespace Shop;

class Billing {
    public function getInvoices($db, $userId) {
        return $db->query("SELECT * FROM invoices WHERE user_id = " . $userId);
    }
}
