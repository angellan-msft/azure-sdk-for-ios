//
//  ViewController.swift
//  AzureSDKDemoSwift
//
//  Created by Travis Prescott on 8/27/19.
//  Copyright © 2019 Azure SDK Team. All rights reserved.
//

import AzureCore
import AzureAppConfiguration
import AzureStorageBlob
import os.log
import UIKit

class MainViewController: UITableViewController {

    // MARK: Properties

    private var dataSource: PagedCollection<BlobContainer>?

    override func viewDidLoad() {
        // If I try to call loadAllSettingsByItem here, the execution hangs...
        super.viewDidLoad()
        loadInitialSettings()
    }

    // MARK: Private Methods

    /// Constructs the PagedCollection and retrieves the first page of results to initalize the table view.
    private func loadInitialSettings() {

        let storageAccountName = AppConstants.storageAccountName
        let blobConnectionString = AppConstants.blobConnectionString

        if let blobClient = try? StorageBlobClient(accountName: storageAccountName,
                                                   connectionString: blobConnectionString) {
            blobClient.listContainers { result, httpResponse in
                switch result {
                case .success(let paged):
                    self.dataSource = paged
                    self.reloadTableView()
                case .failure(let error):
                    os_log("Error: %@", String(describing: error))
                }
            }
        }
    }

    /// For demo purposes only to illustrate usage of the "nextItem" method to retrieve all items.
    /// Requires semaphore to force synchronous behavior, otherwise concurrency issues arise.
    private func loadAllSettingsByItem() {
        var newItem: BlobContainer?
        let semaphore = DispatchSemaphore(value: 0)
        repeat {
            self.dataSource?.nextItem { result in
                defer { semaphore.signal() }
                switch result {
                case .failure(let error):
                    newItem = nil
                    os_log("Error: %@", String(describing: error))
                case .success(let item):
                    newItem = item
                }
            }
            _ = semaphore.wait(wallTimeout: .distantFuture)
        } while(newItem != nil)
    }

    /// Uses asynchronous "nextPage" method to fetch the next page of results and update the table view.
    private func loadMoreSettings() {
        self.dataSource?.nextPage { result in
            switch result {
            case .success:
                self.reloadTableView()
            case .failure(let error):
                os_log("Error: %@", String(describing: error))
            }
        }
    }

    /// Reload the table view on the UI thread.
    private func reloadTableView() {
        DispatchQueue.main.async { [weak self] in
            self?.tableView.reloadData()
        }
    }

    // MARK: - Table view data source

    override func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        guard let data = dataSource?.items else { return 0 }
        return data.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let data = dataSource?.items else {
            fatalError("No data found to construct cell.")
        }
        let cellIdentifier = "CustomTableViewCell"
        guard let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier, for: indexPath) as? CustomTableViewCell else {
            fatalError("The dequeued cell is not an instance of CustomTableViewCell")
        }
        // configure the cell
        let container = data[indexPath.row]
        cell.keyLabel.text = container.name
        cell.valueLabel.text = ""

        // load next page if at the end of the current list
        if indexPath.row == data.count - 10 {
            self.loadMoreSettings()
        }
        return cell
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if segue.identifier == "listContainerBlobs" {
            guard let current = sender as? CustomTableViewCell else { fatalError("Unexpected sender.") }
            if let next = segue.destination as? BlobTableViewController {
                next.containerName = current.keyLabel.text
            }
        }
    }
}